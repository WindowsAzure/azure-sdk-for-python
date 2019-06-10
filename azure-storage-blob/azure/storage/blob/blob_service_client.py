# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

import functools
from typing import (  # pylint: disable=unused-import
    Union, Optional, Any, Iterable, Dict, List,
    TYPE_CHECKING
)
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from ._shared_access_signature import SharedAccessSignature
from .container_client import ContainerClient
from .blob_client import BlobClient
from .models import (
    ContainerProperties,
    StorageServiceProperties,
    ContainerPropertiesPaged
)
from ._generated.models import StorageErrorException
from .common import BlobType
from ._utils import (
    create_client,
    create_pipeline,
    create_configuration,
    get_access_conditions,
    process_storage_error,
    basic_error_map,
    return_response_headers,
    parse_connection_str
)

if TYPE_CHECKING:
    from datetime import datetime
    from azure.core import Configuration
    from azure.core.pipeline.transport import HttpTransport
    from azure.core.pipeline.policies import HTTPPolicy
    from .models import (
        AccountPermissions,
        ResourceTypes,
        BlobProperties,
        SnapshotProperties,
        Logging,
        Metrics,
        RetentionPolicy,
        StaticWebsite,
        CorsRule
    )


class BlobServiceClient(object):

    def __init__(
            self, account_url,  # type: str
            credentials=None,  # type: Optional[HTTPPolicy]
            configuration=None, # type: Optional[Configuration]
            **kwargs  # type: Any
        ):
        # type: (...) -> None
        parsed_url = urlparse(account_url.rstrip('/'))
        self.scheme = parsed_url.scheme
        self.account = parsed_url.hostname.split(".blob.core.")[0]
        self.credentials = credentials
        self.url = account_url if not parsed_url.path else "{}://{}".format(
            self.scheme,
            parsed_url.hostname
        )

        self.require_encryption = kwargs.get('require_encryption', False)
        self.key_encryption_key = kwargs.get('key_encryption_key')
        self.key_resolver_function = kwargs.get('key_resolver_function')

        self._config, self._pipeline = create_pipeline(configuration, credentials, **kwargs)
        self._client = create_client(self.url, self._pipeline)

    @classmethod
    def from_connection_string(
            cls, conn_str,  # type: str
            credentials=None,  # type: Optional[HTTPPolicy]
            configuration=None, # type: Optional[Configuration]
            **kwargs  # type: Any
        ):
        """
        Create BlobServiceClient from a Connection String.

        :param str conn_str: A connection string to an Azure Storage account.
        :param credentials: Optional credentials object to override the SAS key as provided
         in the connection string.
        :param configuration: Optional pipeline configuration settings.
        :type configuration: ~azure.core.configuration.Configuration
        """
        account_url, creds = parse_connection_str(conn_str, credentials)
        return cls(account_url, credentials=creds, configuration=configuration, **kwargs)

    @staticmethod
    def create_configuration(**kwargs):
        # type: (**Any) -> Configuration
        """
        Get an HTTP Pipeline Configuration with all default policies for the Blob
        Storage service.

        :rtype: ~azure.core.configuration.Configuration
        """
        return create_configuration(**kwargs)

    def generate_shared_access_signature(
            self, resource_types,  # type: Union[ResourceTypes, str]
            permission,  # type: Union[AccountPermissions, str]
            expiry,  # type: Optional[Union[datetime, str]]
            start=None,  # type: Optional[Union[datetime, str]]
            ip=None,  # type: Optional[str]
            protocol=None  # type: Optional[str]
        ):
        '''
        Generates a shared access signature for the blob service.
        Use the returned signature with the sas_token parameter of any BlobService.

        :param ResourceTypes resource_types:
            Specifies the resource types that are accessible with the account SAS.
        :param AccountPermissions permission:
            The permissions associated with the shared access signature. The
            user is restricted to operations allowed by the permissions.
            Required unless an id is given referencing a stored access policy
            which contains this field. This field must be omitted if it has been
            specified in an associated stored access policy.
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
        :param str ip:
            Specifies an IP address or a range of IP addresses from which to accept requests.
            If the IP address from which the request originates does not match the IP address
            or address range specified on the SAS token, the request is not authenticated.
            For example, specifying sip=168.1.5.65 or sip=168.1.5.60-168.1.5.70 on the SAS
            restricts the request to those IP addresses.
        :param str protocol:
            Specifies the protocol permitted for a request made. The default value
            is https,http. See :class:`~azure.storage.common.models.Protocol` for possible values.
        :return: A Shared Access Signature (sas) token.
        :rtype: str
        '''
        if not hasattr(self.credentials, 'account_key') and not self.credentials.account_key:
            raise ValueError("No account SAS key available.")

        sas = SharedAccessSignature(self.account, self.credentials.account_key)
        return sas.generate_account(resource_types, permission,
                                    expiry, start=start, ip=ip, protocol=protocol)

    def get_account_information(self, timeout=None):
        # type: (Optional[int]) -> Dict[str, str]
        """
        Gets information related to the storage account.
        The information can also be retrieved if the user has a SAS to a container or blob.

        :returns: A dict of account information (SKU and account type).
        :rtype: dict(str, str)
        """
        try:
            response = self._client.service.get_account_info(cls=return_response_headers)
        except StorageErrorException as error:
            process_storage_error(error)
        return {
            'SKU': response.get('x-ms-sku-name'),
            'AccountType': response.get('x-ms-account-kind')
        }

    def get_service_stats(self, timeout=None, **kwargs):
        # type: (Optional[int], **Any) -> Dict[str, Any]
        """
        Retrieves statistics related to replication for the Blob service. It is
        only available when read-access geo-redundant replication is enabled for
        the storage account.

        With geo-redundant replication, Azure Storage maintains your data durable
        in two locations. In both locations, Azure Storage constantly maintains
        multiple healthy replicas of your data. The location where you read,
        create, update, or delete data is the primary storage account location.
        The primary location exists in the region you choose at the time you
        create an account via the Azure Management Azure classic portal, for
        example, North Central US. The location to which your data is replicated
        is the secondary location. The secondary location is automatically
        determined based on the location of the primary; it is in a second data
        center that resides in the same region as the primary location. Read-only
        access is available from the secondary location, if read-access geo-redundant
        replication is enabled for your storage account.

        :param int timeout:
            The timeout parameter is expressed in seconds.
        :return: The blob service stats.
        :rtype: ~azure.storage.blob._generated.models.StorageServiceStats
        """
        try:
            return self._client.service.get_statistics(timeout=timeout, secondary_storage=True, **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    def get_service_properties(self, timeout=None, **kwargs):
        # type(Optional[int]) -> Dict[str, Any]
        """
        Gets the properties of a storage account's Blob service, including
        Azure Storage Analytics.

        :param int timeout:
            The timeout parameter is expressed in seconds.
        :rtype: ~azure.storage.blob._generated.models.StorageServiceProperties
        """
        try:
            return self._client.service.get_properties(
                timeout=timeout,
                error_map=basic_error_map(),
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    def set_service_properties(
            self, logging=None,  # type: Optional[Union[Logging, Dict[str, Any]]]
            hour_metrics=None,  # type: Optional[Union[Metrics, Dict[str, Any]]]
            minute_metrics=None,  # type: Optional[Union[Metrics, Dict[str, Any]]]
            cors=None,  # type: Optional[List[Union[CorsRule, Dict[str, Any]]]]
            target_version=None,  # type: Optional[str]
            timeout=None,  # type: Optional[int]
            delete_retention_policy=None,  # type: Optional[Union[RetentionPolicy, Dict[str, Any]]]
            static_website=None,  # type: Optional[Union[StaticWebsite, Dict[str, Any]]]
            **kwargs
        ):
        # type: (...) -> None
        """
        Sets the properties of a storage account's Blob service, including
        Azure Storage Analytics. If an element (e.g. Logging) is left as None, the 
        existing settings on the service for that functionality are preserved.

        :param logging:
            Groups the Azure Analytics Logging settings.
        :type logging:
            :class:`~azure.storage.blob.models.Logging`
        :param hour_metrics:
            The hour metrics settings provide a summary of request 
            statistics grouped by API in hourly aggregates for blobs.
        :type hour_metrics:
            :class:`~azure.storage.blob.models.Metrics`
        :param minute_metrics:
            The minute metrics settings provide request statistics 
            for each minute for blobs.
        :type minute_metrics:
            :class:`~azure.storage.blob.models.Metrics`
        :param cors:
            You can include up to five CorsRule elements in the 
            list. If an empty list is specified, all CORS rules will be deleted, 
            and CORS will be disabled for the service.
        :type cors: list(:class:`~azure.storage.blob.models.CorsRule`)
        :param str target_version:
            Indicates the default version to use for requests if an incoming 
            request's version is not specified. 
        :param int timeout:
            The timeout parameter is expressed in seconds.
        :param delete_retention_policy:
            The delete retention policy specifies whether to retain deleted blobs.
            It also specifies the number of days and versions of blob to keep.
        :type delete_retention_policy:
            :class:`~azure.storage.blob..models.RetentionPolicy`
        :param static_website:
            Specifies whether the static website feature is enabled,
            and if yes, indicates the index document and 404 error document to use.
        :type static_website:
            :class:`~azure.storage.blob.models.StaticWebsite`
        :rtype: None
        """
        props = StorageServiceProperties(
            logging=logging,
            hour_metrics=hour_metrics,
            minute_metrics=minute_metrics,
            cors=cors,
            default_service_version=target_version,
            delete_retention_policy=delete_retention_policy,
            static_website=static_website
        )
        try:
            return self._client.service.set_properties(
                props,
                timeout=timeout,
                error_map=basic_error_map(),
                **kwargs)
        except StorageErrorException as error:
            process_storage_error(error)

    def list_containers(
            self, name_starts_with=None,  # type: Optional[str]
            include_metadata=False,  # type: Optional[bool]
            marker=None,  # type: Optional[str]
            timeout=None,  # type: Optional[int]
            **kwargs
        ):
        # type: (...) -> ContainerPropertiesPaged
        """
        Returns a generator to list the containers under the specified account.
        The generator will lazily follow the continuation tokens returned by
        the service and stop when all containers have been returned.

        :param str name_starts_with:
            Filters the results to return only containers whose names
            begin with the specified prefix.
        :param bool include_metadata:
            Specifies that container metadata be returned in the response.
        :param str marker:
            An opaque continuation token. This value can be retrieved from the 
            next_marker field of a previous generator object. If specified,
            this generator will begin returning results from this point.
        :param int timeout:
            The timeout parameter is expressed in seconds.
        :returns: An iterable (auto-paging) of ContainerProperties.
        :rtype: ~azure.core.blob.models.ContainerPropertiesPaged
        """
        include = 'metadata' if include_metadata else None
        results_per_page = kwargs.pop('results_per_page', None)
        command = functools.partial(
            self._client.service.list_containers_segment,
            prefix=name_starts_with,
            include=include,
            timeout=timeout,
            error_map=basic_error_map(),
            **kwargs)
        return ContainerPropertiesPaged(
            command, prefix=name_starts_with, results_per_page=results_per_page, marker=marker)

    def get_container_client(self, container):
        # type: (Union[ContainerProperties, str]) -> ContainerClient
        """
        Get a client to interact with the specified container.
        The container need not already exist.

        :param container: The container for the blob. If specified, this value will override
         a container value specified in the blob URL.
        :type container: str or ~azure.storage.blob.models.ContainerProperties
        :returns: A ContainerClient.
        :rtype: ~azure.core.blob.container_client.ContainerClient
        """
        return ContainerClient(self.url, container=container,
            credentials=self.credentials, configuration=self._config, _pipeline=self._pipeline,
            require_encryption=self.require_encryption, key_encryption_key=self.key_encryption_key,
            key_resolver_function=self.key_resolver_function)

    def get_blob_client(
            self, container,  # type: Union[ContainerProperties, str]
            blob,  # type: Union[BlobProperties, str]
            snapshot=None  # type: Optional[Union[SnapshotProperties, str]]
        ):
        # type: (...) -> BlobClient
        """
        Get a client to interact with the specified blob.
        The blob need not already exist.

        :param container: The container for the blob. If specified, this value will override
         a container value specified in the blob URL.
        :type container: str or ~azure.storage.blob.models.ContainerProperties
        :param blob: The blob with which to interact. If specified, this value will override
         a blob value specified in the blob URL.
        :type blob: str or ~azure.storage.blob.models.BlobProperties
        :param str snapshot: The optional blob snapshot on which to operate.
        :returns: A BlobClient.
        :rtype: ~azure.core.blob.blob_client.BlobClient
        """
        return BlobClient(
            self.url, container=container, blob=blob, snapshot=snapshot,
            credentials=self.credentials, configuration=self._config, _pipeline=self._pipeline,
            require_encryption=self.require_encryption, key_encryption_key=self.key_encryption_key,
            key_resolver_function=self.key_resolver_function)
