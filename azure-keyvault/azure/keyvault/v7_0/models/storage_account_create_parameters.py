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

    All required parameters must be populated in order to send to Azure.

    :param resource_id: Required. Storage account resource id.
    :type resource_id: str
    :param active_key_name: Required. Current active storage account key name.
    :type active_key_name: str
    :param auto_regenerate_key: Required. whether keyvault should manage the
     storage account for the user.
    :type auto_regenerate_key: bool
    :param regeneration_period: The key regeneration time duration specified
     in ISO-8601 format.
    :type regeneration_period: str
    :param storage_account_attributes: The attributes of the storage account.
    :type storage_account_attributes:
     ~azure.keyvault.v7_0.models.StorageAccountAttributes
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
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

    def __init__(self, **kwargs):
        super(StorageAccountCreateParameters, self).__init__(**kwargs)
        self.resource_id = kwargs.get('resource_id', None)
        self.active_key_name = kwargs.get('active_key_name', None)
        self.auto_regenerate_key = kwargs.get('auto_regenerate_key', None)
        self.regeneration_period = kwargs.get('regeneration_period', None)
        self.storage_account_attributes = kwargs.get('storage_account_attributes', None)
        self.tags = kwargs.get('tags', None)
