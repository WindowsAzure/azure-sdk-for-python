# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .store_read_settings_py3 import StoreReadSettings


class FileServerReadSettings(StoreReadSettings):
    """File server read settings.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param type: Required. The read setting type.
    :type type: str
    :param max_concurrent_connections: The maximum concurrent connection count
     for the source data store. Type: integer (or Expression with resultType
     integer).
    :type max_concurrent_connections: object
    :param recursive: If true, files under the folder path will be read
     recursively. Default is true. Type: boolean (or Expression with resultType
     boolean).
    :type recursive: object
    :param wildcard_folder_path: FileServer wildcardFolderPath. Type: string
     (or Expression with resultType string).
    :type wildcard_folder_path: object
    :param wildcard_file_name: FileServer wildcardFileName. Type: string (or
     Expression with resultType string).
    :type wildcard_file_name: object
    :param enable_partition_discovery: Indicates whether to enable partition
     discovery.
    :type enable_partition_discovery: bool
    :param modified_datetime_start: The start of file's modified datetime.
     Type: string (or Expression with resultType string).
    :type modified_datetime_start: object
    :param modified_datetime_end: The end of file's modified datetime. Type:
     string (or Expression with resultType string).
    :type modified_datetime_end: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'type': {'key': 'type', 'type': 'str'},
        'max_concurrent_connections': {'key': 'maxConcurrentConnections', 'type': 'object'},
        'recursive': {'key': 'recursive', 'type': 'object'},
        'wildcard_folder_path': {'key': 'wildcardFolderPath', 'type': 'object'},
        'wildcard_file_name': {'key': 'wildcardFileName', 'type': 'object'},
        'enable_partition_discovery': {'key': 'enablePartitionDiscovery', 'type': 'bool'},
        'modified_datetime_start': {'key': 'modifiedDatetimeStart', 'type': 'object'},
        'modified_datetime_end': {'key': 'modifiedDatetimeEnd', 'type': 'object'},
    }

    def __init__(self, *, type: str, additional_properties=None, max_concurrent_connections=None, recursive=None, wildcard_folder_path=None, wildcard_file_name=None, enable_partition_discovery: bool=None, modified_datetime_start=None, modified_datetime_end=None, **kwargs) -> None:
        super(FileServerReadSettings, self).__init__(additional_properties=additional_properties, type=type, max_concurrent_connections=max_concurrent_connections, **kwargs)
        self.recursive = recursive
        self.wildcard_folder_path = wildcard_folder_path
        self.wildcard_file_name = wildcard_file_name
        self.enable_partition_discovery = enable_partition_discovery
        self.modified_datetime_start = modified_datetime_start
        self.modified_datetime_end = modified_datetime_end
