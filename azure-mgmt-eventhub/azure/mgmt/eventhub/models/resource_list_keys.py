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
    """Namespace/EventHub Connection String.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar primary_connection_string: Primary connection string of the created
     Namespace AuthorizationRule.
    :vartype primary_connection_string: str
    :ivar secondary_connection_string: Secondary connection string of the
     created Namespace AuthorizationRule.
    :vartype secondary_connection_string: str
    :ivar primary_key: A base64-encoded 256-bit primary key for signing and
     validating the SAS token.
    :vartype primary_key: str
    :ivar secondary_key: A base64-encoded 256-bit primary key for signing and
     validating the SAS token.
    :vartype secondary_key: str
    :ivar key_name: A string that describes the AuthorizationRule.
    :vartype key_name: str
    """

    _validation = {
        'primary_connection_string': {'readonly': True},
        'secondary_connection_string': {'readonly': True},
        'primary_key': {'readonly': True},
        'secondary_key': {'readonly': True},
        'key_name': {'readonly': True},
    }

    _attribute_map = {
        'primary_connection_string': {'key': 'primaryConnectionString', 'type': 'str'},
        'secondary_connection_string': {'key': 'secondaryConnectionString', 'type': 'str'},
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
        'key_name': {'key': 'keyName', 'type': 'str'},
    }

    def __init__(self):
        self.primary_connection_string = None
        self.secondary_connection_string = None
        self.primary_key = None
        self.secondary_key = None
        self.key_name = None
