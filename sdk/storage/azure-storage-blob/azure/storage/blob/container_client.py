# pylint: disable=too-many-lines
# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

import functools
from typing import (  # pylint: disable=unused-import
    Union, Optional, Any, Iterable, AnyStr, Dict, List, Tuple, IO, Iterator,
    TYPE_CHECKING
)

try:
    from urllib.parse import urlparse, quote, unquote
except ImportError:
    from urlparse import urlparse # type: ignore
    from urllib2 import quote, unquote # type: ignore

import six

from azure.core.paging import ItemPaged
from azure.core.tracing.decorator import distributed_trace
from azure.core.pipeline.transport import HttpRequest

from ._shared.base_client import StorageAccountHostsMixin, parse_connection_str, parse_query
from ._shared.request_handlers import add_metadata_headers, serialize_iso
from ._shared.response_handlers import (
    process_storage_error,
    return_response_headers,
    return_headers_and_deserialized)
from ._generated import AzureBlobStorage
from ._generated.models import (
    ModifiedAccessConditions,
    StorageErrorException,
    SignedIdentifier)
from ._deserialize import deserialize_container_properties
from .models import ( # pylint: disable=unused-import
    ContainerProperties,
    BlobProperties,
    BlobPropertiesPaged,
    BlobType,
    BlobPrefix)
from .lease import LeaseClient, get_access_conditions
from .blob_client import BlobClient
from ._shared_access_signature import BlobSharedAccessSignature

if TYPE_CHECKING:
    from azure.core.pipeline.transport import HttpTransport, HttpResponse  # pylint: disable=ungrouped-imports
    from azure.core.pipeline.policies import HTTPPolicy # pylint: disable=ungrouped-imports
    from .models import ContainerSasPermissions, PublicAccess
    from datetime import datetime
    from .models import ( # pylint: disable=unused-import
        AccessPolicy,
        ContentSettings,
        PremiumPageBlobTier)


class ContainerClient(StorageAccountHostsMixin):
    """A client to interact with a specific container, although that container
    may not yet exist.

    For operations relating to a specific blob within this container, a blob client can be
    retrieved using the :func:`~get_blob_client` function.

    :ivar str url:
        The full endpoint URL to the Container, including SAS token if used. This could be
        either the primary endpoint, or the secondary endpoint depending on the current `location_mode`.
    :ivar str primary_endpoint:
        The full primary endpoint URL.
    :ivar str primary_hostname:
        The hostname of the primary endpoint.
    :ivar str secondary_endpoint:
        The full secondary endpoint URL if configured. If not available
        a ValueError will be raised. To explicitly specify a secondary hostname, use the optional
        `secondary_hostname` keyword argument on instantiation.
    :ivar str secondary_hostname:
        The hostname of the secondary endpoint. If not available this
        will be None. To explicitly specify a secondary hostname, use the optional
        `secondary_hostname` keyword argument on instantiation.
    :ivar str location_mode:
        The location mode that the client is currently using. By default
        this will be "primary". Options include "primary" and "secondary".
    :param str account_url:
        The full URI to the storage account.
    :param container_name:
        The container for the blob.
    :type container_name: str
    :param credential:
        The credentials with which to authenticate. This is optional if the
        account URL already has a SAS token. The value can be a SAS token string, and account
        shared access key, or an instance of a TokenCredentials class from azure.identity.
        If the URL already has a SAS token, specifying an explicit credential will take priority.

    .. admonition:: Example:

        .. literalinclude:: ../tests/test_blob_samples_containers.py
            :start-after: [START create_container_client_from_service]
            :end-before: [END create_container_client_from_service]
            :language: python
            :dedent: 8
            :caption: Get a ContainerClient from an existing BlobServiceClient.

        .. literalinclude:: ../tests/test_blob_samples_containers.py
            :start-after: [START create_container_client_sasurl]
            :end-before: [END create_container_client_sasurl]
            :language: python
            :dedent: 8
            :caption: Creating the container client directly.
    """
    def __init__(
            self, account_url,  # type: str
            container_name,  # type: str
            credential=None,  # type: Optional[Any]
            **kwargs  # type: Any
        ):
        # type: (...) -> None
        try:
            if not account_url.lower().startswith('http'):
                account_url = "https://" + account_url
        except AttributeError:
            raise ValueError("Container URL must be a string.")
        parsed_url = urlparse(account_url.rstrip('/'))
        if not container_name:
            raise ValueError("Please specify a container name.")
        if not parsed_url.netloc:
            raise ValueError("Invalid URL: {}".format(account_url))

        _, sas_token = parse_query(parsed_url.query)
        self.container_name = container_name
        self._query_str, credential = self._format_query_string(sas_token, credential)
        super(ContainerClient, self).__init__(parsed_url, service='blob', credential=credential, **kwargs)
        self._client = AzureBlobStorage(self.url, pipeline=self._pipeline)

    @classmethod
    def from_container_url(cls, container_url, credential=None, **kwargs):
        # type: (str, Optional[Any], Any) -> ContainerClient
        """Create ContainerClient from a container url.

        :param str container_url:
            The full endpoint URL to the Container, including SAS token if used. This could be
            either the primary endpoint, or the secondary endpoint depending on the current `location_mode`.
        :type container_url: str
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token, or the connection string already has shared
            access key values. The value can be a SAS token string, and account shared access
            key, or an instance of a TokenCredentials class from azure.identity.
            Credentials provided here will take precedence over those in the connection string.
        """
        try:
            if not container_url.lower().startswith('http'):
                container_url = "https://" + container_url
        except AttributeError:
            raise ValueError("Container URL must be a string.")
        parsed_url = urlparse(container_url.rstrip('/'))
        if not parsed_url.netloc:
            raise ValueError("Invalid URL: {}".format(container_url))
        account_url = parsed_url.netloc.rstrip('/') + "?" + parsed_url.query
        container_name = unquote(parsed_url.path.lstrip('/').partition('/')[0])
        if not container_name:
            raise ValueError("Invalid URL. Please provide a  url with a valid container_name")

        return cls(
            account_url, container_name=container_name, credential=credential, **kwargs
        )

    def _format_url(self, hostname):
        container_name = self.container_name
        if isinstance(container_name, six.text_type):
            container_name = container_name.encode('UTF-8')
        return "{}://{}/{}{}".format(
            self.scheme,
            hostname,
            quote(container_name),
            self._query_str)

    @classmethod
    def from_connection_string(
            cls, conn_str,  # type: str
            container_name,  # type: str
            credential=None,  # type: Optional[Any]
            **kwargs  # type: Any
        ):  # type: (...) -> ContainerClient
        """Create ContainerClient from a Connection String.

        :param str conn_str:
            A connection string to an Azure Storage account.
        :param container_name:
            The container for the blob.
        :type container_name: str
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token, or the connection string already has shared
            access key values. The value can be a SAS token string, and account shared access
            key, or an instance of a TokenCredentials class from azure.identity.
            Credentials provided here will take precedence over those in the connection string.

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_authentication.py
                :start-after: [START auth_from_connection_string_container]
                :end-before: [END auth_from_connection_string_container]
                :language: python
                :dedent: 8
                :caption: Creating the ContainerClient from a connection string.
        """
        account_url, secondary, credential = parse_connection_str(conn_str, credential, 'blob')
        if 'secondary_hostname' not in kwargs:
            kwargs['secondary_hostname'] = secondary
        return cls(
            account_url, container_name=container_name, credential=credential, **kwargs)

    def generate_shared_access_signature(
            self, permission=None,  # type: Optional[Union[ContainerSasPermissions, str]]
            expiry=None,  # type: Optional[Union[datetime, str]]
            start=None,  # type: Optional[Union[datetime, str]]
            policy_id=None,  # type: Optional[str]
            ip=None,  # type: Optional[str]
            user_delegation_key=None,  # type: Optional[Any]
            **kwargs # type: Any
        ):
        # type: (...) -> Any
        """Generates a shared access signature for the container.
        Use the returned signature with the credential parameter of any BlobServiceClient,
        ContainerClient or BlobClient.

        :param permission:
            The permissions associated with the shared access signature. The
            user is restricted to operations allowed by the permissions.
            Permissions must be ordered read, write, delete, list.
            Required unless an id is given referencing a stored access policy
            which contains this field. This field must be omitted if it has been
            specified in an associated stored access policy.
        :type permission: str or ~azure.storage.blob.ContainerSasPermissions
        :param expiry:
            The time at which the shared access signature becomes invalid.
            Required unless an id is given referencing a stored access policy
            which contains this field. This field must be omitted if it has
            been specified in an associated stored access policy. Azure will always
            convert values to UTC. If a date is passed in without timezone info, it
            is assumed to be UTC.
        :type expiry: datetime or str
        :param start:
            The time at which the shared access signature becomes valid. If
            omitted, start time for this call is assumed to be the time when the
            storage service receives the request. Azure will always convert values
            to UTC. If a date is passed in without timezone info, it is assumed to
            be UTC.
        :type start: datetime or str
        :param str policy_id:
            A unique value up to 64 characters in length that correlates to a
            stored access policy. To create a stored access policy, use :func:`~set_container_access_policy`.
        :param str ip:
            Specifies an IP address or a range of IP addresses from which to accept requests.
            If the IP address from which the request originates does not match the IP address
            or address range specified on the SAS token, the request is not authenticated.
            For example, specifying ip=168.1.5.65 or ip=168.1.5.60-168.1.5.70 on the SAS
            restricts the request to those IP addresses.
        :param ~azure.storage.blob.UserDelegationKey user_delegation_key:
            Instead of an account key, the user could pass in a user delegation key.
            A user delegation key can be obtained from the service by authenticating with an AAD identity;
            this can be accomplished by calling get_user_delegation_key.
            When present, the SAS is signed with the user delegation key instead.
        :keyword str protocol:
            Specifies the protocol permitted for a request made. The default value is https.
        :keyword str account_name:
            Specifies the account_name when using oauth token as credential. If you use oauth token as credential.
        :keyword str cache_control:
            Response header value for Cache-Control when resource is accessed
            using this shared access signature.
        :keyword str content_disposition:
            Response header value for Content-Disposition when resource is accessed
            using this shared access signature.
        :keyword str content_encoding:
            Response header value for Content-Encoding when resource is accessed
            using this shared access signature.
        :keyword str content_language:
            Response header value for Content-Language when resource is accessed
            using this shared access signature.
        :keyword str content_type:
            Response header value for Content-Type when resource is accessed
            using this shared access signature.
        :return: A Shared Access Signature (sas) token.
        :rtype: str

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START generate_sas_token]
                :end-before: [END generate_sas_token]
                :language: python
                :dedent: 12
                :caption: Generating a sas token.
        """
        protocol = kwargs.pop('protocol', None)
        account_name = kwargs.pop('account_name', None)
        cache_control = kwargs.pop('cache_control', None)
        content_disposition = kwargs.pop('content_disposition', None)
        content_encoding = kwargs.pop('content_encoding', None)
        content_language = kwargs.pop('content_language', None)
        content_type = kwargs.pop('content_type', None)
        if user_delegation_key is not None:
            if not hasattr(self.credential, 'account_name') and not account_name:
                raise ValueError("No account_name available. Please provide account_name parameter.")

            account_name = self.credential.account_name if hasattr(self.credential, 'account_name') else account_name
            sas = BlobSharedAccessSignature(account_name, user_delegation_key=user_delegation_key)
        else:
            if not hasattr(self.credential, 'account_key') and not self.credential.account_key:
                raise ValueError("No account SAS key available.")
            sas = BlobSharedAccessSignature(self.credential.account_name, self.credential.account_key)
        return sas.generate_container(
            self.container_name,
            permission=permission,
            expiry=expiry,
            start=start,
            policy_id=policy_id,
            ip=ip,
            protocol=protocol,
            cache_control=cache_control,
            content_disposition=content_disposition,
            content_encoding=content_encoding,
            content_language=content_language,
            content_type=content_type,
        )

    @distributed_trace
    def create_container(self, metadata=None, public_access=None, **kwargs):
        # type: (Optional[Dict[str, str]], Optional[Union[PublicAccess, str]], **Any) -> None
        """
        Creates a new container under the specified account. If the container
        with the same name already exists, the operation fails.

        :param metadata:
            A dict with name_value pairs to associate with the
            container as metadata. Example:{'Category':'test'}
        :type metadata: dict[str, str]
        :param ~azure.storage.blob.PublicAccess public_access:
            Possible values include: container, blob.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START create_container]
                :end-before: [END create_container]
                :language: python
                :dedent: 12
                :caption: Creating a container to store blobs.
        """
        headers = kwargs.pop('headers', {})
        timeout = kwargs.pop('timeout', None)
        headers.update(add_metadata_headers(metadata)) # type: ignore
        try:
            return self._client.container.create( # type: ignore
                timeout=timeout,
                access=public_access,
                cls=return_response_headers,
                headers=headers,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def delete_container(
            self, **kwargs):
        # type: (Any) -> None
        """
        Marks the specified container for deletion. The container and any blobs
        contained within it are later deleted during garbage collection.

        :keyword ~azure.storage.blob.LeaseClient lease:
            If specified, delete_container only succeeds if the
            container's lease is active and matches this ID.
            Required if the container has an active lease.
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str if_match:
            An ETag value, or the wildcard character (*). Specify this header to perform
            the operation only if the resource's ETag matches the value specified.
        :keyword str if_none_match:
            An ETag value, or the wildcard character (*). Specify this header
            to perform the operation only if the resource's ETag does not match
            the value specified. Specify the wildcard character (*) to perform
            the operation only if the resource does not exist, and fail the
            operation if it does exist.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START delete_container]
                :end-before: [END delete_container]
                :language: python
                :dedent: 12
                :caption: Delete a container.
        """
        lease = kwargs.pop('lease', None)
        access_conditions = get_access_conditions(lease)
        mod_conditions = ModifiedAccessConditions(
            if_modified_since=kwargs.pop('if_modified_since', None),
            if_unmodified_since=kwargs.pop('if_unmodified_since', None),
            if_match=kwargs.pop('if_match', None),
            if_none_match=kwargs.pop('if_none_match', None))
        timeout = kwargs.pop('timeout', None)
        try:
            self._client.container.delete(
                timeout=timeout,
                lease_access_conditions=access_conditions,
                modified_access_conditions=mod_conditions,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def acquire_lease(
            self, lease_duration=-1,  # type: int
            lease_id=None,  # type: Optional[str]
            **kwargs):
        # type: (...) -> LeaseClient
        """
        Requests a new lease. If the container does not have an active lease,
        the Blob service creates a lease on the container and returns a new
        lease ID.

        :param int lease_duration:
            Specifies the duration of the lease, in seconds, or negative one
            (-1) for a lease that never expires. A non-infinite lease can be
            between 15 and 60 seconds. A lease duration cannot be changed
            using renew or change. Default is -1 (infinite lease).
        :param str lease_id:
            Proposed lease ID, in a GUID string format. The Blob service returns
            400 (Invalid request) if the proposed lease ID is not in the correct format.
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str if_match:
            An ETag value, or the wildcard character (*). Specify this header to perform
            the operation only if the resource's ETag matches the value specified.
        :keyword str if_none_match:
            An ETag value, or the wildcard character (*). Specify this header
            to perform the operation only if the resource's ETag does not match
            the value specified. Specify the wildcard character (*) to perform
            the operation only if the resource does not exist, and fail the
            operation if it does exist.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: A LeaseClient object, that can be run in a context manager.
        :rtype: ~azure.storage.blob.LeaseClient

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START acquire_lease_on_container]
                :end-before: [END acquire_lease_on_container]
                :language: python
                :dedent: 8
                :caption: Acquiring a lease on the container.
        """
        lease = LeaseClient(self, lease_id=lease_id) # type: ignore
        kwargs.setdefault('merge_span', True)
        timeout = kwargs.pop('timeout', None)
        lease.acquire(lease_duration=lease_duration, timeout=timeout, **kwargs)
        return lease

    @distributed_trace
    def get_account_information(self, **kwargs): # type: ignore
        # type: (**Any) -> Dict[str, str]
        """Gets information related to the storage account.

        The information can also be retrieved if the user has a SAS to a container or blob.
        The keys in the returned dictionary include 'sku_name' and 'account_kind'.

        :returns: A dict of account information (SKU and account type).
        :rtype: dict(str, str)
        """
        try:
            return self._client.container.get_account_info(cls=return_response_headers, **kwargs) # type: ignore
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def get_container_properties(self, **kwargs):
        # type: (Any) -> ContainerProperties
        """Returns all user-defined metadata and system properties for the specified
        container. The data returned does not include the container's list of blobs.

        :keyword ~azure.storage.blob.LeaseClient lease:
            If specified, get_container_properties only succeeds if the
            container's lease is active and matches this ID.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: Properties for the specified container within a container object.
        :rtype: ~azure.storage.blob.ContainerProperties

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START get_container_properties]
                :end-before: [END get_container_properties]
                :language: python
                :dedent: 12
                :caption: Getting properties on the container.
        """
        lease = kwargs.pop('lease', None)
        access_conditions = get_access_conditions(lease)
        timeout = kwargs.pop('timeout', None)
        try:
            response = self._client.container.get_properties(
                timeout=timeout,
                lease_access_conditions=access_conditions,
                cls=deserialize_container_properties,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)
        response.name = self.container_name
        return response # type: ignore

    @distributed_trace
    def set_container_metadata( # type: ignore
            self, metadata=None,  # type: Optional[Dict[str, str]]
            **kwargs
        ):
        # type: (...) -> Dict[str, Union[str, datetime]]
        """Sets one or more user-defined name-value pairs for the specified
        container. Each call to this operation replaces all existing metadata
        attached to the container. To remove all metadata from the container,
        call this operation with no metadata dict.

        :param metadata:
            A dict containing name-value pairs to associate with the container as
            metadata. Example: {'category':'test'}
        :type metadata: dict[str, str]
        :keyword str lease:
            If specified, set_container_metadata only succeeds if the
            container's lease is active and matches this ID.
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: Container-updated property dict (Etag and last modified).

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START set_container_metadata]
                :end-before: [END set_container_metadata]
                :language: python
                :dedent: 12
                :caption: Setting metadata on the container.
        """
        headers = kwargs.pop('headers', {})
        headers.update(add_metadata_headers(metadata))
        lease = kwargs.pop('lease', None)
        access_conditions = get_access_conditions(lease)
        mod_conditions = ModifiedAccessConditions(if_modified_since=kwargs.pop('if_modified_since', None))
        timeout = kwargs.pop('timeout', None)
        try:
            return self._client.container.set_metadata( # type: ignore
                timeout=timeout,
                lease_access_conditions=access_conditions,
                modified_access_conditions=mod_conditions,
                cls=return_response_headers,
                headers=headers,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def get_container_access_policy(self, **kwargs):
        # type: (Any) -> Dict[str, Any]
        """Gets the permissions for the specified container.
        The permissions indicate whether container data may be accessed publicly.

        :keyword str lease:
            If specified, get_container_access_policy only succeeds if the
            container's lease is active and matches this ID.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: Access policy information in a dict.
        :rtype: dict[str, str]

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START get_container_access_policy]
                :end-before: [END get_container_access_policy]
                :language: python
                :dedent: 12
                :caption: Getting the access policy on the container.
        """
        lease = kwargs.pop('lease', None)
        access_conditions = get_access_conditions(lease)
        timeout = kwargs.pop('timeout', None)
        try:
            response, identifiers = self._client.container.get_access_policy(
                timeout=timeout,
                lease_access_conditions=access_conditions,
                cls=return_headers_and_deserialized,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)
        return {
            'public_access': response.get('blob_public_access'),
            'signed_identifiers': identifiers or []
        }

    @distributed_trace
    def set_container_access_policy(
            self, signed_identifiers=None,  # type: Optional[Dict[str, Optional[AccessPolicy]]]
            public_access=None,  # type: Optional[Union[str, PublicAccess]]
            **kwargs
        ):  # type: (...) -> Dict[str, Union[str, datetime]]
        """Sets the permissions for the specified container or stored access
        policies that may be used with Shared Access Signatures. The permissions
        indicate whether blobs in a container may be accessed publicly.

        :param signed_identifiers:
            A dictionary of access policies to associate with the container. The
            dictionary may contain up to 5 elements. An empty dictionary
            will clear the access policies set on the service.
        :type signed_identifiers: dict[str, ~azure.storage.blob.AccessPolicy]
        :param ~azure.storage.blob.PublicAccess public_access:
            Possible values include: container, blob.
        :keyword lease:
            Required if the container has an active lease. Value can be a LeaseClient object
            or the lease ID as a string.
        :type lease: ~azure.storage.blob.LeaseClient or str
        :keyword ~datetime.datetime if_modified_since:
            A datetime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified date/time.
        :keyword ~datetime.datetime if_unmodified_since:
            A datetime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: Container-updated property dict (Etag and last modified).
        :rtype: dict[str, str or ~datetime.datetime]

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START set_container_access_policy]
                :end-before: [END set_container_access_policy]
                :language: python
                :dedent: 12
                :caption: Setting access policy on the container.
        """
        if signed_identifiers:
            if len(signed_identifiers) > 5:
                raise ValueError(
                    'Too many access policies provided. The server does not support setting '
                    'more than 5 access policies on a single resource.')
            identifiers = []
            for key, value in signed_identifiers.items():
                if value:
                    value.start = serialize_iso(value.start)
                    value.expiry = serialize_iso(value.expiry)
                identifiers.append(SignedIdentifier(id=key, access_policy=value)) # type: ignore
            signed_identifiers = identifiers # type: ignore
        lease = kwargs.pop('lease', None)
        mod_conditions = ModifiedAccessConditions(
            if_modified_since=kwargs.pop('if_modified_since', None),
            if_unmodified_since=kwargs.pop('if_unmodified_since', None))
        access_conditions = get_access_conditions(lease)
        timeout = kwargs.pop('timeout', None)
        try:
            return self._client.container.set_access_policy(
                container_acl=signed_identifiers or None,
                timeout=timeout,
                access=public_access,
                lease_access_conditions=access_conditions,
                modified_access_conditions=mod_conditions,
                cls=return_response_headers,
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    @distributed_trace
    def list_blobs(self, name_starts_with=None, include=None, **kwargs):
        # type: (Optional[str], Optional[Any], **Any) -> ItemPaged[BlobProperties]
        """Returns a generator to list the blobs under the specified container.
        The generator will lazily follow the continuation tokens returned by
        the service.

        :param str name_starts_with:
            Filters the results to return only blobs whose names
            begin with the specified prefix.
        :param list[str] include:
            Specifies one or more additional datasets to include in the response.
            Options include: 'snapshots', 'metadata', 'uncommittedblobs', 'copy', 'deleted'.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: An iterable (auto-paging) response of BlobProperties.
        :rtype: ~azure.core.paging.ItemPaged[~azure.storage.blob.BlobProperties]

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START list_blobs_in_container]
                :end-before: [END list_blobs_in_container]
                :language: python
                :dedent: 8
                :caption: List the blobs in the container.
        """
        if include and not isinstance(include, list):
            include = [include]

        results_per_page = kwargs.pop('results_per_page', None)
        timeout = kwargs.pop('timeout', None)
        command = functools.partial(
            self._client.container.list_blob_flat_segment,
            include=include,
            timeout=timeout,
            **kwargs)
        return ItemPaged(
            command, prefix=name_starts_with, results_per_page=results_per_page,
            page_iterator_class=BlobPropertiesPaged)

    @distributed_trace
    def walk_blobs(
            self, name_starts_with=None, # type: Optional[str]
            include=None, # type: Optional[Any]
            delimiter="/", # type: str
            **kwargs # type: Optional[Any]
        ):
        # type: (...) -> ItemPaged[BlobProperties]
        """Returns a generator to list the blobs under the specified container.
        The generator will lazily follow the continuation tokens returned by
        the service. This operation will list blobs in accordance with a hierarchy,
        as delimited by the specified delimiter character.

        :param str name_starts_with:
            Filters the results to return only blobs whose names
            begin with the specified prefix.
        :param list[str] include:
            Specifies one or more additional datasets to include in the response.
            Options include: 'snapshots', 'metadata', 'uncommittedblobs', 'copy', 'deleted'.
        :param str delimiter:
            When the request includes this parameter, the operation returns a BlobPrefix
            element in the response body that acts as a placeholder for all blobs whose
            names begin with the same substring up to the appearance of the delimiter
            character. The delimiter may be a single character or a string.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :returns: An iterable (auto-paging) response of BlobProperties.
        :rtype: ~azure.core.paging.ItemPaged[~azure.storage.blob.BlobProperties]
        """
        if include and not isinstance(include, list):
            include = [include]

        results_per_page = kwargs.pop('results_per_page', None)
        timeout = kwargs.pop('timeout', None)
        command = functools.partial(
            self._client.container.list_blob_hierarchy_segment,
            delimiter=delimiter,
            include=include,
            timeout=timeout,
            **kwargs)
        return BlobPrefix(
            command,
            prefix=name_starts_with,
            results_per_page=results_per_page,
            delimiter=delimiter)

    @distributed_trace
    def upload_blob(
            self, name,  # type: Union[str, BlobProperties]
            data,  # type: Union[Iterable[AnyStr], IO[AnyStr]]
            blob_type=BlobType.BlockBlob,  # type: Union[str, BlobType]
            length=None,  # type: Optional[int]
            metadata=None,  # type: Optional[Dict[str, str]]
            encoding='UTF-8', # type: str
            **kwargs
        ):
        # type: (...) -> BlobClient
        """Creates a new blob from a data source with automatic chunking.

        :param name: The blob with which to interact. If specified, this value will override
            a blob value specified in the blob URL.
        :type name: str or ~azure.storage.blob.BlobProperties
        :param ~azure.storage.blob.BlobType blob_type: The type of the blob. This can be
            either BlockBlob, PageBlob or AppendBlob. The default value is BlockBlob.
        :param int length:
            Number of bytes to read from the stream. This is optional, but
            should be supplied for optimal performance.
        :param metadata:
            Name-value pairs associated with the blob as metadata.
        :type metadata: dict(str, str)
        :param str encoding:
            Defaults to UTF-8.
        :keyword bool overwrite: Whether the blob to be uploaded should overwrite the current data.
            If True, upload_blob will silently overwrite the existing data. If set to False, the
            operation will fail with ResourceExistsError. The exception to the above is with Append
            blob types. In this case, if data already exists, an error will not be raised and
            the data will be appended to the existing blob. If you set overwrite=True, then the existing
            blob will be deleted, and a new one created.
        :keyword ~azure.storage.blob.ContentSettings content_settings:
            ContentSettings object used to set blob properties.
        :keyword bool validate_content:
            If true, calculates an MD5 hash for each chunk of the blob. The storage
            service checks the hash of the content that has arrived with the hash
            that was sent. This is primarily valuable for detecting bitflips on
            the wire if using http instead of https as https (the default) will
            already validate. Note that this MD5 hash is not stored with the
            blob. Also note that if enabled, the memory-efficient upload algorithm
            will not be used, because computing the MD5 hash requires buffering
            entire blocks, and doing so defeats the purpose of the memory-efficient algorithm.
        :keyword lease:
            Required if the container has an active lease. Value can be a LeaseClient object
            or the lease ID as a string.
        :type lease: ~azure.storage.blob.LeaseClient or str
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str if_match:
            An ETag value, or the wildcard character (*). Specify this header to perform
            the operation only if the resource's ETag matches the value specified.
        :keyword str if_none_match:
            An ETag value, or the wildcard character (*). Specify this header
            to perform the operation only if the resource's ETag does not match
            the value specified. Specify the wildcard character (*) to perform
            the operation only if the resource does not exist, and fail the
            operation if it does exist.
        :keyword int timeout:
            The timeout parameter is expressed in seconds. This method may make
            multiple calls to the Azure service and the timeout will apply to
            each call individually.
        :keyword ~azure.storage.blob.PremiumPageBlobTier premium_page_blob_tier:
            A page blob tier value to set the blob to. The tier correlates to the size of the
            blob and number of allowed IOPS. This is only applicable to page blobs on
            premium storage accounts.
        :keyword ~azure.storage.blob.StandardBlobTier standard_blob_tier:
            A standard blob tier value to set the blob to. For this version of the library,
            this is only applicable to block blobs on standard storage accounts.
        :keyword int maxsize_condition:
            Optional conditional header. The max length in bytes permitted for
            the append blob. If the Append Block operation would cause the blob
            to exceed that limit or if the blob size is already greater than the
            value specified in this header, the request will fail with
            MaxBlobSizeConditionNotMet error (HTTP status code 412 - Precondition Failed).
        :keyword int max_concurrency:
            Maximum number of parallel connections to use when the blob size exceeds
            64MB.
        :keyword ~azure.storage.blob.CustomerProvidedEncryptionKey cpk:
            Encrypts the data on the service-side with the given key.
            Use of customer-provided keys must be done over HTTPS.
            As the encryption key itself is provided in the request,
            a secure connection must be established to transfer the key.
        :returns: A BlobClient to interact with the newly uploaded blob.
        :rtype: ~azure.storage.blob.BlobClient

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START upload_blob_to_container]
                :end-before: [END upload_blob_to_container]
                :language: python
                :dedent: 8
                :caption: Upload blob to the container.
        """
        blob = self.get_blob_client(name)
        kwargs.setdefault('merge_span', True)
        timeout = kwargs.pop('timeout', None)
        blob.upload_blob(
            data,
            blob_type=blob_type,
            length=length,
            metadata=metadata,
            timeout=timeout,
            encoding=encoding,
            **kwargs
        )
        return blob

    @distributed_trace
    def delete_blob(
            self, blob,  # type: Union[str, BlobProperties]
            delete_snapshots=None,  # type: Optional[str]
            **kwargs
        ):
        # type: (...) -> None
        """Marks the specified blob or snapshot for deletion.

        The blob is later deleted during garbage collection.
        Note that in order to delete a blob, you must delete all of its
        snapshots. You can delete both at the same time with the Delete
        Blob operation.

        If a delete retention policy is enabled for the service, then this operation soft deletes the blob or snapshot
        and retains the blob or snapshot for specified number of days.
        After specified number of days, blob's data is removed from the service during garbage collection.
        Soft deleted blob or snapshot is accessible through List Blobs API specifying `include="deleted"` option.
        Soft-deleted blob or snapshot can be restored using Undelete API.

        :param blob: The blob with which to interact. If specified, this value will override
         a blob value specified in the blob URL.
        :type blob: str or ~azure.storage.blob.BlobProperties
        :param str delete_snapshots:
            Required if the blob has associated snapshots. Values include:
             - "only": Deletes only the blobs snapshots.
             - "include": Deletes the blob along with all snapshots.
        :param str delete_snapshots:
            Required if the blob has associated snapshots. Values include:
             - "only": Deletes only the blobs snapshots.
             - "include": Deletes the blob along with all snapshots.
        :keyword lease:
            Required if the blob has an active lease. Value can be a Lease object
            or the lease ID as a string.
        :type lease: ~azure.storage.blob.LeaseClient or str
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str if_match:
            An ETag value, or the wildcard character (*). Specify this header to perform
            the operation only if the resource's ETag matches the value specified.
        :keyword str if_none_match:
            An ETag value, or the wildcard character (*). Specify this header
            to perform the operation only if the resource's ETag does not match
            the value specified. Specify the wildcard character (*) to perform
            the operation only if the resource does not exist, and fail the
            operation if it does exist.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :rtype: None
        """
        blob = self.get_blob_client(blob) # type: ignore
        kwargs.setdefault('merge_span', True)
        timeout = kwargs.pop('timeout', None)
        blob.delete_blob( # type: ignore
            delete_snapshots=delete_snapshots,
            timeout=timeout,
            **kwargs)

    def _generate_delete_blobs_options(
        self, snapshot=None,
        delete_snapshots=None,
        request_id=None,
        lease_access_conditions=None,
        modified_access_conditions=None,
        **kwargs
    ):
        """This code is a copy from _generated.

        Once Autorest is able to provide request preparation this code should be removed.
        """
        lease_id = None
        if lease_access_conditions is not None:
            lease_id = lease_access_conditions.lease_id
        if_modified_since = None
        if modified_access_conditions is not None:
            if_modified_since = modified_access_conditions.if_modified_since
        if_unmodified_since = None
        if modified_access_conditions is not None:
            if_unmodified_since = modified_access_conditions.if_unmodified_since
        if_match = None
        if modified_access_conditions is not None:
            if_match = modified_access_conditions.if_match
        if_none_match = None
        if modified_access_conditions is not None:
            if_none_match = modified_access_conditions.if_none_match

        # Construct parameters
        timeout = kwargs.pop('timeout', None)
        query_parameters = {}
        if snapshot is not None:
            query_parameters['snapshot'] = self._client._serialize.query("snapshot", snapshot, 'str')  # pylint: disable=protected-access
        if timeout is not None:
            query_parameters['timeout'] = self._client._serialize.query("timeout", timeout, 'int', minimum=0)  # pylint: disable=protected-access

        # Construct headers
        header_parameters = {}
        if delete_snapshots is not None:
            header_parameters['x-ms-delete-snapshots'] = self._client._serialize.header(  # pylint: disable=protected-access
                "delete_snapshots", delete_snapshots, 'DeleteSnapshotsOptionType')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._client._serialize.header(  # pylint: disable=protected-access
                "request_id", request_id, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._client._serialize.header(  # pylint: disable=protected-access
                "lease_id", lease_id, 'str')
        if if_modified_since is not None:
            header_parameters['If-Modified-Since'] = self._client._serialize.header(  # pylint: disable=protected-access
                "if_modified_since", if_modified_since, 'rfc-1123')
        if if_unmodified_since is not None:
            header_parameters['If-Unmodified-Since'] = self._client._serialize.header(  # pylint: disable=protected-access
                "if_unmodified_since", if_unmodified_since, 'rfc-1123')
        if if_match is not None:
            header_parameters['If-Match'] = self._client._serialize.header(  # pylint: disable=protected-access
                "if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._client._serialize.header(  # pylint: disable=protected-access
                "if_none_match", if_none_match, 'str')

        return query_parameters, header_parameters

    @distributed_trace
    def delete_blobs(self, *blobs, **kwargs):
        # type: (...) -> Iterator[HttpResponse]
        """Marks the specified blobs or snapshots for deletion.

        The blob is later deleted during garbage collection.
        Note that in order to delete a blob, you must delete all of its
        snapshots. You can delete both at the same time with the Delete
        Blob operation.

        If a delete retention policy is enabled for the service, then this operation soft deletes the blob or snapshot
        and retains the blob or snapshot for specified number of days.
        After specified number of days, blob's data is removed from the service during garbage collection.
        Soft deleted blob or snapshot is accessible through List Blobs API specifying `include="deleted"` option.
        Soft-deleted blob or snapshot can be restored using Undelete API.

        :param blobs: The blobs with which to interact.
        :type blobs: str or ~azure.storage.blob.BlobProperties
        :keyword str delete_snapshots:
            Required if the blob has associated snapshots. Values include:
             - "only": Deletes only the blobs snapshots.
             - "include": Deletes the blob along with all snapshots.
        :keyword lease:
            Required if the blob has an active lease. Value can be a Lease object
            or the lease ID as a string.
        :type lease: ~azure.storage.blob.LeaseClient or str
        :keyword str delete_snapshots:
            Required if the blob has associated snapshots. Values include:
             - "only": Deletes only the blobs snapshots.
             - "include": Deletes the blob along with all snapshots.
        :keyword ~datetime.datetime if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str if_match:
            An ETag value, or the wildcard character (*). Specify this header to perform
            the operation only if the resource's ETag matches the value specified.
        :keyword str if_none_match:
            An ETag value, or the wildcard character (*). Specify this header
            to perform the operation only if the resource's ETag does not match
            the value specified. Specify the wildcard character (*) to perform
            the operation only if the resource does not exist, and fail the
            operation if it does exist.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: An iterator of responses, one for each blob in order
        :rtype: iterator[~azure.core.pipeline.transport.HttpResponse]
        """
        options = BlobClient._generic_delete_blob_options(  # pylint: disable=protected-access
            **kwargs
        )
        query_parameters, header_parameters = self._generate_delete_blobs_options(**options)
        # To pass kwargs to "_batch_send", we need to remove anything that was
        # in the Autorest signature for Autorest, otherwise transport will be upset
        for possible_param in ['timeout', 'delete_snapshots', 'lease_access_conditions', 'modified_access_conditions']:
            options.pop(possible_param, None)

        reqs = []
        for blob in blobs:
            req = HttpRequest(
                "DELETE",
                "/{}/{}".format(self.container_name, blob),
                headers=header_parameters
            )
            req.format_parameters(query_parameters)
            reqs.append(req)

        return self._batch_send(*reqs, **options)

    def _generate_set_tier_options(
        self, tier, rehydrate_priority=None, request_id=None, lease_access_conditions=None, **kwargs
    ):
        """This code is a copy from _generated.

        Once Autorest is able to provide request preparation this code should be removed.
        """
        lease_id = None
        if lease_access_conditions is not None:
            lease_id = lease_access_conditions.lease_id

        comp = "tier"
        timeout = kwargs.pop('timeout', None)
        # Construct parameters
        query_parameters = {}
        if timeout is not None:
            query_parameters['timeout'] = self._client._serialize.query("timeout", timeout, 'int', minimum=0)  # pylint: disable=protected-access
        query_parameters['comp'] = self._client._serialize.query("comp", comp, 'str')  # pylint: disable=protected-access, specify-parameter-names-in-call

        # Construct headers
        header_parameters = {}
        header_parameters['x-ms-access-tier'] = self._client._serialize.header("tier", tier, 'str')  # pylint: disable=protected-access, specify-parameter-names-in-call
        if rehydrate_priority is not None:
            header_parameters['x-ms-rehydrate-priority'] = self._client._serialize.header(  # pylint: disable=protected-access
                "rehydrate_priority", rehydrate_priority, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._client._serialize.header(  # pylint: disable=protected-access
                "request_id", request_id, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._client._serialize.header("lease_id", lease_id, 'str')  # pylint: disable=protected-access

        return query_parameters, header_parameters

    @distributed_trace
    def set_standard_blob_tier_blobs(
        self,
        standard_blob_tier,  # type: Union[str, StandardBlobTier]
        *blobs,  # type: Union[str, BlobProperties]
        **kwargs
    ):
        # type: (...) -> Iterator[HttpResponse]
        """This operation sets the tier on block blobs.

        A block blob's tier determines Hot/Cool/Archive storage type.
        This operation does not update the blob's ETag.

        :param blobs: The blobs with which to interact.
        :type blobs: str or ~azure.storage.blob.BlobProperties
        :param standard_blob_tier:
            Indicates the tier to be set on the blob. Options include 'Hot', 'Cool',
            'Archive'. The hot tier is optimized for storing data that is accessed
            frequently. The cool storage tier is optimized for storing data that
            is infrequently accessed and stored for at least a month. The archive
            tier is optimized for storing data that is rarely accessed and stored
            for at least six months with flexible latency requirements.
        :type standard_blob_tier: str or ~azure.storage.blob.StandardBlobTier
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :keyword lease:
            Required if the blob has an active lease. Value can be a LeaseClient object
            or the lease ID as a string.
        :type lease: ~azure.storage.blob.LeaseClient or str
        :return: An iterator of responses, one for each blob in order
        :rtype: iterator[~azure.core.pipeline.transport.HttpResponse]
        """
        access_conditions = get_access_conditions(kwargs.pop('lease', None))
        if standard_blob_tier is None:
            raise ValueError("A StandardBlobTier must be specified")

        query_parameters, header_parameters = self._generate_set_tier_options(
            tier=standard_blob_tier,
            lease_access_conditions=access_conditions,
            **kwargs
        )
        # To pass kwargs to "_batch_send", we need to remove anything that was
        # in the Autorest signature for Autorest, otherwise transport will be upset
        for possible_param in ['timeout', 'lease']:
            kwargs.pop(possible_param, None)

        reqs = []
        for blob in blobs:
            req = HttpRequest(
                "PUT",
                "/{}/{}".format(self.container_name, blob),
                headers=header_parameters
            )
            req.format_parameters(query_parameters)
            reqs.append(req)

        return self._batch_send(*reqs, **kwargs)

    @distributed_trace
    def set_premium_page_blob_tier_blobs(
        self,
        premium_page_blob_tier,  # type: Union[str, PremiumPageBlobTier]
        *blobs,  # type: Union[str, BlobProperties]
        **kwargs
    ):
        # type: (...) -> Iterator[HttpResponse]
        """Sets the page blob tiers on the blobs. This API is only supported for page blobs on premium accounts.

        :param blobs: The blobs with which to interact.
        :type blobs: str or ~azure.storage.blob.BlobProperties
        :param premium_page_blob_tier:
            A page blob tier value to set the blob to. The tier correlates to the size of the
            blob and number of allowed IOPS. This is only applicable to page blobs on
            premium storage accounts.
        :type premium_page_blob_tier: ~azure.storage.blob.PremiumPageBlobTier
        :keyword int timeout:
            The timeout parameter is expressed in seconds. This method may make
            multiple calls to the Azure service and the timeout will apply to
            each call individually.
        :keyword lease:
            Required if the blob has an active lease. Value can be a LeaseClient object
            or the lease ID as a string.
        :type lease: ~azure.storage.blob.LeaseClient or str
        :return: An iterator of responses, one for each blob in order
        :rtype: iterator[~azure.core.pipeline.transport.HttpResponse]
        """
        access_conditions = get_access_conditions(kwargs.pop('lease', None))
        if premium_page_blob_tier is None:
            raise ValueError("A PremiumPageBlobTier must be specified")

        query_parameters, header_parameters = self._generate_set_tier_options(
            tier=premium_page_blob_tier,
            lease_access_conditions=access_conditions,
            **kwargs
        )
        # To pass kwargs to "_batch_send", we need to remove anything that was
        # in the Autorest signature for Autorest, otherwise transport will be upset
        for possible_param in ['timeout', 'lease']:
            kwargs.pop(possible_param, None)

        reqs = []
        for blob in blobs:
            req = HttpRequest(
                "PUT",
                "/{}/{}".format(self.container_name, blob),
                headers=header_parameters
            )
            req.format_parameters(query_parameters)
            reqs.append(req)

        return self._batch_send(*reqs, **kwargs)

    def get_blob_client(
            self, blob,  # type: Union[str, BlobProperties]
            snapshot=None  # type: str
        ):
        # type: (...) -> BlobClient
        """Get a client to interact with the specified blob.

        The blob need not already exist.

        :param blob:
            The blob with which to interact.
        :type blob: str or ~azure.storage.blob.BlobProperties
        :param str snapshot:
            The optional blob snapshot on which to operate.
        :returns: A BlobClient.
        :rtype: ~azure.storage.blob.BlobClient

        .. admonition:: Example:

            .. literalinclude:: ../tests/test_blob_samples_containers.py
                :start-after: [START get_blob_client]
                :end-before: [END get_blob_client]
                :language: python
                :dedent: 8
                :caption: Get the blob client.
        """
        try:
            blob_name = blob.name
        except AttributeError:
            blob_name = blob
        return BlobClient(
            self.url, container_name=self.container_name, blob_name=blob_name, snapshot=snapshot,
            credential=self.credential, _configuration=self._config,
            _pipeline=self._pipeline, _location_mode=self._location_mode, _hosts=self._hosts,
            require_encryption=self.require_encryption, key_encryption_key=self.key_encryption_key,
            key_resolver_function=self.key_resolver_function)
