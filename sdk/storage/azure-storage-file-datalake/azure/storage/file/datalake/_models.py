# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
# pylint: disable=too-few-public-methods, too-many-instance-attributes
# pylint: disable=super-init-not-called, too-many-lines
from enum import Enum
from azure.core.paging import PageIterator
from azure.storage.blob import ContainerProperties, LeaseProperties, ContentSettings, ContainerSasPermissions, \
    BlobSasPermissions, AccessPolicy, BlobProperties, ResourceTypes, AccountSasPermissions, UserDelegationKey
from azure.storage.blob._generated.models import StorageErrorException
from azure.storage.blob._models import ContainerPropertiesPaged, BlobPropertiesPaged
from azure.storage.blob._shared.response_handlers import process_storage_error, return_context_and_deserialized
from azure.storage.file.datalake._deserialize import return_headers_and_deserialized_path_list
from azure.storage.file.datalake._generated.models import Path


class FileSystemProperties(ContainerProperties):
    def __init__(self, **kwargs):
        super(FileSystemProperties, self).__init__(
            **kwargs
        )


class FileSystemPropertiesPaged(ContainerPropertiesPaged):
    def __init__(self, *args, **kwargs):
        super(FileSystemPropertiesPaged, self).__init__(
            *args,
            **kwargs
        )

    @staticmethod
    def _build_item(item):
        return FileSystemProperties._from_generated(item)  # pylint: disable=protected-access


class DirectoryProperties(BlobProperties):
    def __init__(self, **kwargs):
        super(DirectoryProperties, self).__init__(
            **kwargs
        )


class FileProperties(BlobProperties):
    def __init__(self, **kwargs):
        super(DirectoryProperties, self).__init__(
            **kwargs
        )


class PathProperties(object):
    def __init__(self, **kwargs):
        super(PathProperties, self).__init__(
            **kwargs
        )
        self.name = kwargs.pop('name', None)
        self.owner = kwargs.get('owner', None)
        self.group = kwargs.get('group', None)
        self.permissions = kwargs.get('permissions', None)
        self.last_modified = kwargs.get('last_modified', None)
        self.is_directory = kwargs.get('is_directory', None)
        self.etag = kwargs.get('etag', None)
        self.content_length = kwargs.get('content_length', None)

    @classmethod
    def _from_generated(cls, generated):
        path_prop = PathProperties()
        path_prop.name = generated.name
        path_prop.owner = generated.owner
        path_prop.group = generated.group
        path_prop.permissions = generated.permissions
        path_prop.last_modified = generated.last_modified
        path_prop.is_directory = generated.is_directory
        path_prop.etag =generated.additional_properties.get('etag')
        path_prop.content_length = generated.content_length
        return path_prop


class PathPropertiesPaged(PageIterator):
    """An Iterable of Blob properties.

    :ivar str path: Filters the results to return only paths under the specified path.
    :ivar int results_per_page: The maximum number of results retrieved per API call.
    :ivar str continuation_token: The continuation token to retrieve the next page of results.
    :ivar list(~azure.storage.file.datalake.PathProperties) current_page: The current page of listed results.

    :param callable command: Function to retrieve the next page of items.
    :param str path: Filters the results to return only paths under the specified path.
    :param int max_results: The maximum number of blobs to retrieve per
        call.
    :param str continuation_token: An opaque continuation token.
    """
    def __init__(
            self, command,
            recursive,
            path=None,
            max_results=None,
            continuation_token=None,
            upn=None):
        super(PathPropertiesPaged, self).__init__(
            get_next=self._get_next_cb,
            extract_data=self._extract_data_cb,
            continuation_token=continuation_token or ""
        )
        self._command = command
        self.recursive = recursive
        self.results_per_page = max_results
        self.path = path
        self.upn = upn
        self.current_page = None

    def _get_next_cb(self, continuation_token):
        try:
            return self._command(
                self.recursive,
                continuation=continuation_token or None,
                path=self.path,
                max_results=self.results_per_page,
                upn=self.upn,
                cls=return_headers_and_deserialized_path_list)
        except StorageErrorException as error:
            process_storage_error(error)

    def _extract_data_cb(self, get_next_return):
        self.path_list, self._response = get_next_return
        self.current_page = [self._build_item(item) for item in self.path_list]

        return self._response['continuation'] or None, self.current_page

    def _build_item(self, item):
        if isinstance(item, PathProperties):
            return item
        if isinstance(item, Path):
            path = PathProperties._from_generated(item)  # pylint: disable=protected-access
            return path
        return item


class LeaseProperties(LeaseProperties):
    """DataLake Lease Properties.

    :param str status:
        The lease status of the file. Possible values: locked|unlocked
    :param str state:
        Lease state of the file. Possible values: available|leased|expired|breaking|broken
    :param str duration:
        When a file is leased, specifies whether the lease is of infinite or fixed duration.
    """
    def __init__(self, **kwargs):
        super(LeaseProperties, self).__init__(
            **kwargs
        )


class ContentSettings(ContentSettings):
    """The content settings of a file or directory.

    :ivar str content_type:
        The content type specified for the file or directory. If no content type was
        specified, the default content type is application/octet-stream.
    :ivar str content_encoding:
        If the content_encoding has previously been set
        for the file, that value is stored.
    :ivar str content_language:
        If the content_language has previously been set
        for the file, that value is stored.
    :ivar str content_disposition:
        content_disposition conveys additional information about how to
        process the response payload, and also can be used to attach
        additional metadata. If content_disposition has previously been set
        for the file, that value is stored.
    :ivar str cache_control:
        If the cache_control has previously been set for
        the file, that value is stored.
    :ivar str content_md5:
        If the content_md5 has been set for the file, this response
        header is stored so that the client can check for message content
        integrity.
    """
    def __init__(
            self, content_type=None, content_encoding=None,
            content_language=None, content_disposition=None,
            cache_control=None, content_md5=None, **kwargs):
        super(ContentSettings, self).__init__(
            content_type=content_type,
            content_encoding=content_encoding,
            content_language=content_language,
            content_disposition=content_disposition,
            cache_control=cache_control,
            content_md5=content_md5,
            **kwargs
        )


class AccountSasPermissions(AccountSasPermissions):
    def __init__(self, read=False, write=False, delete=False, list=False, create=False):
        super(AccountSasPermissions, self).__init__(
            read=read, create=create, write=write,
            delete=delete
        )


class FileSystemSasPermissions(ContainerSasPermissions):
    """FileSystemSasPermissions class to be used with the
    :func:`~azure.storage.file.datalake.generate_file_system_sas` function.

    :param bool read:
        Read the content, properties, metadata etc.
    :param bool write:
        Create or write content, properties, metadata. Lease the file system.
    :param bool delete:
        Delete the file system.
    :param bool list:
        List paths in the file system.
    """
    def __init__(self, read=False, write=False, delete=False, list=False):
        super(FileSystemSasPermissions, self).__init__(
            read=read, write=write, delete=delete, list=list
        )


class DirectorySasPermissions(BlobSasPermissions):
    """DirectorySasPermissions class to be used with the
    :func:`~azure.storage.file.datalake.generate_directory_sas` function.

    :param bool read:
        Read the content, properties, metadata etc.
    :param bool create:
        Create a new directory
    :param bool write:
        Create or write content, properties, metadata. Lease the directory.
    :param bool delete:
        Delete the directory.
    """
    def __init__(self, read=False, create=False, write=False,
                 delete=False):
        super(DirectorySasPermissions, self).__init__(
            read=read, create=create, write=write,
            delete=delete
        )


class FileSasPermissions(BlobSasPermissions):
    """FileSasPermissions class to be used with the
    :func:`~azure.storage.file.datalake.generate_file_sas` function.

    :param bool read:
        Read the content, properties, metadata etc. Use the file as
        the source of a read operation.
    :param bool create:
        Write a new file
    :param bool write:
        Create or write content, properties, metadata. Lease the file.
    :param bool delete:
        Delete the file.
    """
    def __init__(self, read=False, create=False, write=False,
                 delete=False):
        super(FileSasPermissions, self).__init__(
            read=read, create=create, write=write,
            delete=delete
        )


class ResourceTypes(ResourceTypes):
    """
    Specifies the resource types that are accessible with the account SAS.

    :param bool service:
        Access to service-level APIs (e.g.List File Systems)
    :param bool file_system:
        Access to file_system-level APIs (e.g., Create/Delete file system,
        List Directories/Files)
    :param bool object:
        Access to object-level APIs for
        files(e.g. Create File, etc.)
    """
    def __init__(self, service=False, file_system=False, object=False):
        super(ResourceTypes, self).__init__(service=service, container=file_system, object=object)


class UserDelegationKey(UserDelegationKey):
    """
    Represents a user delegation key, provided to the user by Azure Storage
    based on their Azure Active Directory access token.

    The fields are saved as simple strings since the user does not have to interact with this object;
    to generate an identify SAS, the user can simply pass it to the right API.

    :ivar str signed_oid:
        Object ID of this token.
    :ivar str signed_tid:
        Tenant ID of the tenant that issued this token.
    :ivar str signed_start:
        The datetime this token becomes valid.
    :ivar str signed_expiry:
        The datetime this token expires.
    :ivar str signed_service:
        What service this key is valid for.
    :ivar str signed_version:
        The version identifier of the REST service that created this token.
    :ivar str value:
        The user delegation key.
    """
    def _init(self):
        super(UserDelegationKey, self).__init__()


class PublicAccess(str, Enum):
    """
    Specifies whether data in the file system may be accessed publicly and the level of access.
    """

    OFF = 'off'
    """
    Specifies that there is no public read access for both the file systems and files within the file system.
    Clients cannot enumerate the file systems within the storage account as well as the files within the file system.
    """

    File = 'blob'
    """
    Specifies public read access for files. file data within this file system can be read
    via anonymous request, but file system data is not available. Clients cannot enumerate
    files within the container via anonymous request.
    """

    FileSystem = 'container'
    """
    Specifies full public read access for file system and file data. Clients can enumerate
    files within the file system via anonymous request, but cannot enumerate file systems
    within the storage account.
    """


class LocationMode(object):
    """
    Specifies the location the request should be sent to. This mode only applies
    for RA-GRS accounts which allow secondary read access. All other account types
    must use PRIMARY.
    """

    PRIMARY = 'primary'  #: Requests should be sent to the primary location.
    SECONDARY = 'secondary'  #: Requests should be sent to the secondary location, if possible.