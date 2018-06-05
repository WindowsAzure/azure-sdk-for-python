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


class ResourceListKeys(Model):
    """Namespace/NotificationHub Connection String.

    :param primary_connection_string: PrimaryConnectionString of the
     AuthorizationRule.
    :type primary_connection_string: str
    :param secondary_connection_string: SecondaryConnectionString of the
     created AuthorizationRule
    :type secondary_connection_string: str
    :param primary_key: PrimaryKey of the created AuthorizationRule.
    :type primary_key: str
    :param secondary_key: SecondaryKey of the created AuthorizationRule
    :type secondary_key: str
    :param key_name: KeyName of the created AuthorizationRule
    :type key_name: str
    """

    _attribute_map = {
        'primary_connection_string': {'key': 'primaryConnectionString', 'type': 'str'},
        'secondary_connection_string': {'key': 'secondaryConnectionString', 'type': 'str'},
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
        'key_name': {'key': 'keyName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ResourceListKeys, self).__init__(**kwargs)
        self.primary_connection_string = kwargs.get('primary_connection_string', None)
        self.secondary_connection_string = kwargs.get('secondary_connection_string', None)
        self.primary_key = kwargs.get('primary_key', None)
        self.secondary_key = kwargs.get('secondary_key', None)
        self.key_name = kwargs.get('key_name', None)
