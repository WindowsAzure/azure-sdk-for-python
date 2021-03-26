# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from typing import Any, Union

try:
    from urllib.parse import quote, unquote
except ImportError:
    from urllib2 import quote, unquote # type: ignore
from azure.core.pipeline import Pipeline
from ._deserialize import deserialize_dir_properties
from ._shared.base_client import TransportWrapper, parse_connection_str
from ._data_lake_file_client import DataLakeFileClient
from ._models import DirectoryProperties, FileProperties
from ._path_client import PathClient


class DataLakeDirectoryClient(PathClient):
    """A client to interact with the DataLake directory, even if the directory may not yet exist.

    For operations relating to a specific subdirectory or file under the directory, a directory client or file client
    can be retrieved using the :func:`~get_sub_directory_client` or :func:`~get_file_client` functions.

    :ivar str url:
        The full endpoint URL to the file system, including SAS token if used.
    :ivar str primary_endpoint:
        The full primary endpoint URL.
    :ivar str primary_hostname:
        The hostname of the primary endpoint.
    :param str account_url:
        The URI to the storage account.
    :param file_system_name:
        The file system for the directory or files.
    :type file_system_name: str
    :param directory_name:
        The whole path of the directory. eg. {directory under file system}/{directory to interact with}
    :type directory_name: str
    :param credential:
        The credentials with which to authenticate. This is optional if the
        account URL already has a SAS token. The value can be a SAS token string,
        an instance of a AzureSasCredential from azure.core.credentials, and account
        shared access key, or an instance of a TokenCredentials class from azure.identity.
        If the resource URI already contains a SAS token, this will be ignored in favor of an explicit credential
        - except in the case of AzureSasCredential, where the conflicting SAS tokens will raise a ValueError.

    .. admonition:: Example:

        .. literalinclude:: ../samples/datalake_samples_instantiate_client.py
            :start-after: [START instantiate_directory_client_from_conn_str]
            :end-before: [END instantiate_directory_client_from_conn_str]
            :language: python
            :dedent: 4
            :caption: Creating the DataLakeServiceClient from connection string.
    """
    def __init__(
        self, account_url,  # type: str
        file_system_name,  # type: str
        directory_name,  # type: str
        credential=None,  # type: Optional[Any]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        super(DataLakeDirectoryClient, self).__init__(account_url, file_system_name, path_name=directory_name,
                                                      credential=credential, **kwargs)

    @classmethod
    def from_connection_string(
            cls, conn_str,  # type: str
            file_system_name,  # type: str
            directory_name,  # type: str
            credential=None,  # type: Optional[Any]
            **kwargs  # type: Any
        ):  # type: (...) -> DataLakeDirectoryClient
        """
        Create DataLakeDirectoryClient from a Connection String.

        :param str conn_str:
            A connection string to an Azure Storage account.
        :param file_system_name:
            The name of file system to interact with.
        :type file_system_name: str
        :param directory_name:
            The name of directory to interact with. The directory is under file system.
        :type directory_name: str
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token, or the connection string already has shared
            access key values. The value can be a SAS token string,
            an instance of a AzureSasCredential from azure.core.credentials, and account shared access
            key, or an instance of a TokenCredentials class from azure.identity.
            Credentials provided here will take precedence over those in the connection string.
        :return a DataLakeDirectoryClient
        :rtype ~azure.storage.filedatalake.DataLakeDirectoryClient
        """
        account_url, _, credential = parse_connection_str(conn_str, credential, 'dfs')
        return cls(
            account_url, file_system_name=file_system_name, directory_name=directory_name,
            credential=credential, **kwargs)

    def create_directory(self, metadata=None,  # type: Optional[Dict[str, str]]
                         **kwargs):
        # type: (...) -> Dict[str, Union[str, datetime]]
        """
        Create a new directory.

        :param metadata:
            Name-value pairs associated with the file as metadata.
        :type metadata: dict(str, str)
        :keyword ~azure.storage.filedatalake.ContentSettings content_settings:
            ContentSettings object used to set path properties.
        :keyword lease:
            Required if the file has an active lease. Value can be a DataLakeLeaseClient object
            or the lease ID as a string.
        :paramtype lease: ~azure.storage.filedatalake.DataLakeLeaseClient or str
        :keyword str umask:
            Optional and only valid if Hierarchical Namespace is enabled for the account.
            When creating a file or directory and the parent folder does not have a default ACL,
            the umask restricts the permissions of the file or directory to be created.
            The resulting permission is given by p & ^u, where p is the permission and u is the umask.
            For example, if p is 0777 and u is 0057, then the resulting permission is 0720.
            The default permission is 0777 for a directory and 0666 for a file. The default umask is 0027.
            The umask must be specified in 4-digit octal notation (e.g. 0766).
        :keyword str permissions:
            Optional and only valid if Hierarchical Namespace
            is enabled for the account. Sets POSIX access permissions for the file
            owner, the file owning group, and others. Each class may be granted
            read, write, or execute permission.  The sticky bit is also supported.
            Both symbolic (rwxrw-rw-) and 4-digit octal notation (e.g. 0766) are
            supported.
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
        :keyword str etag:
            An ETag value, or the wildcard character (*). Used to check if the resource has changed,
            and act according to the condition specified by the `match_condition` parameter.
        :keyword ~azure.core.MatchConditions match_condition:
            The match condition to use upon the etag.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: response dict (Etag and last modified).

        .. admonition:: Example:

            .. literalinclude:: ../samples/datalake_samples_directory.py
                :start-after: [START create_directory]
                :end-before: [END create_directory]
                :language: python
                :dedent: 8
                :caption: Create directory.
        """
        return self._create('directory', metadata=metadata, **kwargs)

    def delete_directory(self, **kwargs):
        # type: (...) -> None
        """
        Marks the specified directory for deletion.

        :keyword lease:
            Required if the file has an active lease. Value can be a LeaseClient object
            or the lease ID as a string.
        :paramtype lease: ~azure.storage.filedatalake.DataLakeLeaseClient or str
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
        :keyword str etag:
            An ETag value, or the wildcard character (*). Used to check if the resource has changed,
            and act according to the condition specified by the `match_condition` parameter.
        :keyword ~azure.core.MatchConditions match_condition:
            The match condition to use upon the etag.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/datalake_samples_directory.py
                :start-after: [START delete_directory]
                :end-before: [END delete_directory]
                :language: python
                :dedent: 4
                :caption: Delete directory.
        """
        return self._delete(**kwargs)

    def get_directory_properties(self, **kwargs):
        # type: (**Any) -> DirectoryProperties
        """Returns all user-defined metadata, standard HTTP properties, and
        system properties for the directory. It does not return the content of the directory.

        :keyword lease:
            Required if the directory or file has an active lease. Value can be a DataLakeLeaseClient object
            or the lease ID as a string.
        :paramtype lease: ~azure.storage.filedatalake.DataLakeLeaseClient or str
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
        :keyword str etag:
            An ETag value, or the wildcard character (*). Used to check if the resource has changed,
            and act according to the condition specified by the `match_condition` parameter.
        :keyword ~azure.core.MatchConditions match_condition:
            The match condition to use upon the etag.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :rtype: DirectoryProperties

        .. admonition:: Example:

            .. literalinclude:: ../samples/datalake_samples_directory.py
                :start-after: [START get_directory_properties]
                :end-before: [END get_directory_properties]
                :language: python
                :dedent: 4
                :caption: Getting the properties for a file/directory.
        """
        return self._get_path_properties(cls=deserialize_dir_properties, **kwargs)  # pylint: disable=protected-access

    def exists(self, **kwargs):
        # type: (**Any) -> bool
        """
        Returns True if a directory exists and returns False otherwise.

        :kwarg int timeout:
            The timeout parameter is expressed in seconds.
        :returns: boolean
        """
        return self._exists(**kwargs)

    def rename_directory(self, new_name, **kwargs):
        # type: (str, **Any) -> DataLakeDirectoryClient
        """
        Rename the source directory.

        :param str new_name:
            the new directory name the user want to rename to.
            The value must have the following format: "{filesystem}/{directory}/{subdirectory}".
        :keyword source_lease:
            A lease ID for the source path. If specified,
            the source path must have an active lease and the leaase ID must
            match.
        :paramtype source_lease: ~azure.storage.filedatalake.DataLakeLeaseClient or str
        :keyword lease:
            Required if the file/directory has an active lease. Value can be a LeaseClient object
            or the lease ID as a string.
        :paramtype lease: ~azure.storage.filedatalake.DataLakeLeaseClient or str
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
        :keyword str etag:
            An ETag value, or the wildcard character (*). Used to check if the resource has changed,
            and act according to the condition specified by the `match_condition` parameter.
        :keyword ~azure.core.MatchConditions match_condition:
            The match condition to use upon the etag.
        :keyword ~datetime.datetime source_if_modified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only
            if the resource has been modified since the specified time.
        :keyword ~datetime.datetime source_if_unmodified_since:
            A DateTime value. Azure expects the date value passed in to be UTC.
            If timezone is included, any non-UTC datetimes will be converted to UTC.
            If a date is passed in without timezone info, it is assumed to be UTC.
            Specify this header to perform the operation only if
            the resource has not been modified since the specified date/time.
        :keyword str source_etag:
            The source ETag value, or the wildcard character (*). Used to check if the resource has changed,
            and act according to the condition specified by the `match_condition` parameter.
        :keyword ~azure.core.MatchConditions source_match_condition:
            The source match condition to use upon the etag.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: DataLakeDirectoryClient

        .. admonition:: Example:

            .. literalinclude:: ../samples/datalake_samples_directory.py
                :start-after: [START rename_directory]
                :end-before: [END rename_directory]
                :language: python
                :dedent: 4
                :caption: Rename the source directory.
        """
        new_name = new_name.strip('/')
        new_file_system = new_name.split('/')[0]
        new_path_and_token = new_name[len(new_file_system):].strip('/').split('?')
        new_path = new_path_and_token[0]
        try:
            new_dir_sas = new_path_and_token[1] or self._query_str.strip('?')
        except IndexError:
            if not self._raw_credential and new_file_system != self.file_system_name:
                raise ValueError("please provide the sas token for the new file")
            if not self._raw_credential and new_file_system == self.file_system_name:
                new_dir_sas = self._query_str.strip('?')

        new_directory_client = DataLakeDirectoryClient(
            "{}://{}".format(self.scheme, self.primary_hostname), new_file_system, directory_name=new_path,
            credential=self._raw_credential or new_dir_sas,
            _hosts=self._hosts, _configuration=self._config, _pipeline=self._pipeline,
            require_encryption=self.require_encryption,
            key_encryption_key=self.key_encryption_key,
            key_resolver_function=self.key_resolver_function)
        new_directory_client._rename_path(  # pylint: disable=protected-access
            '/{}/{}{}'.format(quote(unquote(self.file_system_name)),
                              quote(unquote(self.path_name)),
                              self._query_str),
            **kwargs)
        return new_directory_client

    def create_sub_directory(self, sub_directory,  # type: Union[DirectoryProperties, str]
                             metadata=None,  # type: Optional[Dict[str, str]]
                             **kwargs):
        # type: (...) -> DataLakeDirectoryClient
        """
        Create a subdirectory and return the subdirectory client to be interacted with.

        :param sub_directory:
            The directory with which to interact. This can either be the name of the directory,
            or an instance of DirectoryProperties.
        :type sub_directory: str or ~azure.storage.filedatalake.DirectoryProperties
        :param metadata:
            Name-value pairs associated with the file as metadata.
        :type metadata: dict(str, str)
        :keyword ~azure.storage.filedatalake.ContentSettings content_settings:
            ContentSettings object used to set path properties.
        :keyword lease:
            Required if the file has an active lease. Value can be a DataLakeLeaseClient object
            or the lease ID as a string.
        :paramtype lease: ~azure.storage.filedatalake.DataLakeLeaseClient or str
        :keyword str umask:
            Optional and only valid if Hierarchical Namespace is enabled for the account.
            When creating a file or directory and the parent folder does not have a default ACL,
            the umask restricts the permissions of the file or directory to be created.
            The resulting permission is given by p & ^u, where p is the permission and u is the umask.
            For example, if p is 0777 and u is 0057, then the resulting permission is 0720.
            The default permission is 0777 for a directory and 0666 for a file. The default umask is 0027.
            The umask must be specified in 4-digit octal notation (e.g. 0766).
        :keyword str permissions:
            Optional and only valid if Hierarchical Namespace
            is enabled for the account. Sets POSIX access permissions for the file
            owner, the file owning group, and others. Each class may be granted
            read, write, or execute permission.  The sticky bit is also supported.
            Both symbolic (rwxrw-rw-) and 4-digit octal notation (e.g. 0766) are
            supported.
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
        :keyword str etag:
            An ETag value, or the wildcard character (*). Used to check if the resource has changed,
            and act according to the condition specified by the `match_condition` parameter.
        :keyword ~azure.core.MatchConditions match_condition:
            The match condition to use upon the etag.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: DataLakeDirectoryClient for the subdirectory.
        """
        subdir = self.get_sub_directory_client(sub_directory)
        subdir.create_directory(metadata=metadata, **kwargs)
        return subdir

    def delete_sub_directory(self, sub_directory,  # type: Union[DirectoryProperties, str]
                             **kwargs):
        # type: (...) -> DataLakeDirectoryClient
        """
        Marks the specified subdirectory for deletion.

        :param sub_directory:
            The directory with which to interact. This can either be the name of the directory,
            or an instance of DirectoryProperties.
        :type sub_directory: str or ~azure.storage.filedatalake.DirectoryProperties
        :keyword lease:
            Required if the file has an active lease. Value can be a LeaseClient object
            or the lease ID as a string.
        :paramtype lease: ~azure.storage.filedatalake.DataLakeLeaseClient or str
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
        :keyword str etag:
            An ETag value, or the wildcard character (*). Used to check if the resource has changed,
            and act according to the condition specified by the `match_condition` parameter.
        :keyword ~azure.core.MatchConditions match_condition:
            The match condition to use upon the etag.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: DataLakeDirectoryClient for the subdirectory
        """
        subdir = self.get_sub_directory_client(sub_directory)
        subdir.delete_directory(**kwargs)
        return subdir

    def create_file(self, file,  # type: Union[FileProperties, str]
                    **kwargs):
        # type: (...) -> DataLakeFileClient
        """
        Create a new file and return the file client to be interacted with.

        :param file:
            The file with which to interact. This can either be the name of the file,
            or an instance of FileProperties.
        :type file: str or ~azure.storage.filedatalake.FileProperties
        :keyword ~azure.storage.filedatalake.ContentSettings content_settings:
            ContentSettings object used to set path properties.
        :keyword metadata:
            Name-value pairs associated with the file as metadata.
        :type metadata: dict(str, str)
        :keyword lease:
            Required if the file has an active lease. Value can be a DataLakeLeaseClient object
            or the lease ID as a string.
        :paramtype lease: ~azure.storage.filedatalake.DataLakeLeaseClient or str
        :keyword str umask:
            Optional and only valid if Hierarchical Namespace is enabled for the account.
            When creating a file or directory and the parent folder does not have a default ACL,
            the umask restricts the permissions of the file or directory to be created.
            The resulting permission is given by p & ^u, where p is the permission and u is the umask.
            For example, if p is 0777 and u is 0057, then the resulting permission is 0720.
            The default permission is 0777 for a directory and 0666 for a file. The default umask is 0027.
            The umask must be specified in 4-digit octal notation (e.g. 0766).
        :keyword str permissions:
            Optional and only valid if Hierarchical Namespace
            is enabled for the account. Sets POSIX access permissions for the file
            owner, the file owning group, and others. Each class may be granted
            read, write, or execute permission.  The sticky bit is also supported.
            Both symbolic (rwxrw-rw-) and 4-digit octal notation (e.g. 0766) are
            supported.
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
        :keyword str etag:
            An ETag value, or the wildcard character (*). Used to check if the resource has changed,
            and act according to the condition specified by the `match_condition` parameter.
        :keyword ~azure.core.MatchConditions match_condition:
            The match condition to use upon the etag.
        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: DataLakeFileClient
        """
        file_client = self.get_file_client(file)
        file_client.create_file(**kwargs)
        return file_client

    def get_file_client(self, file, **kwargs):
        # type: (Union[FileProperties, str], Any) -> DataLakeFileClient
        """Get a client to interact with the specified file.

        The file need not already exist.

        :param file:
            The file with which to interact. This can either be the name of the file,
            or an instance of FileProperties. eg. directory/subdirectory/file
        :type file: str or ~azure.storage.filedatalake.FileProperties
        :kwarg str snapshot:
            The optional file snapshot on which to operate. This can be the snapshot ID string
            or the response returned from :func:`create_snapshot`.
        :returns: A DataLakeFileClient.
        :rtype: ~azure.storage.filedatalake.DataLakeFileClient
        """
        try:
            file_path = file.get('name')
        except AttributeError:
            file_path = self.path_name + '/' + str(file)

        _pipeline = Pipeline(
            transport=TransportWrapper(self._pipeline._transport), # pylint: disable = protected-access
            policies=self._pipeline._impl_policies # pylint: disable = protected-access
        )
        return DataLakeFileClient(
            self.url, self.file_system_name, file_path=file_path, credential=self._raw_credential,
            _hosts=self._hosts, _configuration=self._config, _pipeline=self._pipeline,
            require_encryption=self.require_encryption,
            key_encryption_key=self.key_encryption_key,
            key_resolver_function=self.key_resolver_function, snapshot=kwargs.pop("snapshot", None))

    def get_sub_directory_client(self, sub_directory  # type: Union[DirectoryProperties, str]
                                 ):
        # type: (...) -> DataLakeDirectoryClient
        """Get a client to interact with the specified subdirectory of the current directory.

        The sub subdirectory need not already exist.

        :param sub_directory:
            The directory with which to interact. This can either be the name of the directory,
            or an instance of DirectoryProperties.
        :type sub_directory: str or ~azure.storage.filedatalake.DirectoryProperties
        :returns: A DataLakeDirectoryClient.
        :rtype: ~azure.storage.filedatalake.DataLakeDirectoryClient
        """
        try:
            subdir_path = sub_directory.get('name')
        except AttributeError:
            subdir_path = self.path_name + '/' + str(sub_directory)

        _pipeline = Pipeline(
            transport=TransportWrapper(self._pipeline._transport), # pylint: disable = protected-access
            policies=self._pipeline._impl_policies # pylint: disable = protected-access
        )
        return DataLakeDirectoryClient(
            self.url, self.file_system_name, directory_name=subdir_path, credential=self._raw_credential,
            _hosts=self._hosts, _configuration=self._config, _pipeline=self._pipeline,
            require_encryption=self.require_encryption,
            key_encryption_key=self.key_encryption_key,
            key_resolver_function=self.key_resolver_function)
