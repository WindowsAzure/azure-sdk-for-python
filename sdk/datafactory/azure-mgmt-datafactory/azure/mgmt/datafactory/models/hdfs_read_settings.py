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

from .store_read_settings import StoreReadSettings


class HdfsReadSettings(StoreReadSettings):
    """HDFS read settings.

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
    :param wildcard_folder_path: HDFS wildcardFolderPath. Type: string (or
     Expression with resultType string).
    :type wildcard_folder_path: object
    :param wildcard_file_name: HDFS wildcardFileName. Type: string (or
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
    :param distcp_settings: Specifies Distcp-related settings.
    :type distcp_settings: ~azure.mgmt.datafactory.models.DistcpSettings
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
        'distcp_settings': {'key': 'distcpSettings', 'type': 'DistcpSettings'},
    }

    def __init__(self, **kwargs):
        super(HdfsReadSettings, self).__init__(**kwargs)
        self.recursive = kwargs.get('recursive', None)
        self.wildcard_folder_path = kwargs.get('wildcard_folder_path', None)
        self.wildcard_file_name = kwargs.get('wildcard_file_name', None)
        self.enable_partition_discovery = kwargs.get('enable_partition_discovery', None)
        self.modified_datetime_start = kwargs.get('modified_datetime_start', None)
        self.modified_datetime_end = kwargs.get('modified_datetime_end', None)
        self.distcp_settings = kwargs.get('distcp_settings', None)
