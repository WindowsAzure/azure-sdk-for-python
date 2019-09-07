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

from .store_write_settings_py3 import StoreWriteSettings


class AzureBlobFSWriteSettings(StoreWriteSettings):
    """Azure blobFS write settings.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param max_concurrent_connections: The maximum concurrent connection count
     for the source data store. Type: integer (or Expression with resultType
     integer).
    :type max_concurrent_connections: object
    :param copy_behavior: The type of copy behavior for copy sink.
    :type copy_behavior: object
    :param type: Required. Constant filled by server.
    :type type: str
    :param block_size_in_mb: Indicates the block size(MB) when writing data to
     blob. Type: integer (or Expression with resultType integer).
    :type block_size_in_mb: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'max_concurrent_connections': {'key': 'maxConcurrentConnections', 'type': 'object'},
        'copy_behavior': {'key': 'copyBehavior', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
        'block_size_in_mb': {'key': 'blockSizeInMB', 'type': 'object'},
    }

    def __init__(self, *, additional_properties=None, max_concurrent_connections=None, copy_behavior=None, block_size_in_mb=None, **kwargs) -> None:
        super(AzureBlobFSWriteSettings, self).__init__(additional_properties=additional_properties, max_concurrent_connections=max_concurrent_connections, copy_behavior=copy_behavior, **kwargs)
        self.block_size_in_mb = block_size_in_mb
        self.type = 'AzureBlobFSWriteSettings'
