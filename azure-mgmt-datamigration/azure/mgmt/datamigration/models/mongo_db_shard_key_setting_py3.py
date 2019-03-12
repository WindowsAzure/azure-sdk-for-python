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


class MongoDbShardKeySetting(Model):
    """Describes a MongoDB shard key.

    All required parameters must be populated in order to send to Azure.

    :param fields: Required. The fields within the shard key
    :type fields: list[~azure.mgmt.datamigration.models.MongoDbShardKeyField]
    :param is_unique: Required. Whether the shard key is unique
    :type is_unique: bool
    """

    _validation = {
        'fields': {'required': True},
        'is_unique': {'required': True},
    }

    _attribute_map = {
        'fields': {'key': 'fields', 'type': '[MongoDbShardKeyField]'},
        'is_unique': {'key': 'isUnique', 'type': 'bool'},
    }

    def __init__(self, *, fields, is_unique: bool, **kwargs) -> None:
        super(MongoDbShardKeySetting, self).__init__(**kwargs)
        self.fields = fields
        self.is_unique = is_unique
