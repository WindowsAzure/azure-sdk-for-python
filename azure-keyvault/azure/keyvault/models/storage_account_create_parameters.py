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

from msrest.serialization import Model


class StorageAccountCreateParameters(Model):
    """The storage account create parameters.

    :param resource_id: Storage account resource id.
    :type resource_id: str
    :param active_key_name: Current active storage account key name.
    :type active_key_name: str
    :param auto_regenerate_key: whether keyvault should manage the storage
     account for the user.
    :type auto_regenerate_key: bool
    :param regeneration_period: The key regeneration time duration specified
     in ISO-8601 format.
    :type regeneration_period: str
    :param storage_account_attributes: The attributes of the storage account.
    :type storage_account_attributes: :class:`StorageAccountAttributes
     <azure.keyvault.models.StorageAccountAttributes>`
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict
    """

    _validation = {
        'resource_id': {'required': True},
        'active_key_name': {'required': True},
        'auto_regenerate_key': {'required': True},
    }

    _attribute_map = {
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'active_key_name': {'key': 'activeKeyName', 'type': 'str'},
        'auto_regenerate_key': {'key': 'autoRegenerateKey', 'type': 'bool'},
        'regeneration_period': {'key': 'regenerationPeriod', 'type': 'str'},
        'storage_account_attributes': {'key': 'attributes', 'type': 'StorageAccountAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, resource_id, active_key_name, auto_regenerate_key, regeneration_period=None, storage_account_attributes=None, tags=None):
        self.resource_id = resource_id
        self.active_key_name = active_key_name
        self.auto_regenerate_key = auto_regenerate_key
        self.regeneration_period = regeneration_period
        self.storage_account_attributes = storage_account_attributes
        self.tags = tags
