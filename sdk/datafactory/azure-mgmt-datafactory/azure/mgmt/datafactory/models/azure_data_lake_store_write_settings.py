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

from .store_write_settings import StoreWriteSettings


class AzureDataLakeStoreWriteSettings(StoreWriteSettings):
    """Azure data lake store write settings.

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
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'max_concurrent_connections': {'key': 'maxConcurrentConnections', 'type': 'object'},
        'copy_behavior': {'key': 'copyBehavior', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AzureDataLakeStoreWriteSettings, self).__init__(**kwargs)
        self.type = 'AzureDataLakeStoreWriteSettings'
