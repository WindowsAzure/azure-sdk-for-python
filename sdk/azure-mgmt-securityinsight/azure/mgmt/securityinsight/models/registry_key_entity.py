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

from .entity import Entity


class RegistryKeyEntity(Entity):
    """Represents a registry key entity.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :ivar additional_data: A bag of custom fields that should be part of the
     entity and will be presented to the user.
    :vartype additional_data: dict[str, object]
    :ivar friendly_name: The graph item display name which is a short humanly
     readable description of the graph item instance. This property is optional
     and might be system generated.
    :vartype friendly_name: str
    :ivar hive: the hive that holds the registry key. Possible values include:
     'HKEY_LOCAL_MACHINE', 'HKEY_CLASSES_ROOT', 'HKEY_CURRENT_CONFIG',
     'HKEY_USERS', 'HKEY_CURRENT_USER_LOCAL_SETTINGS', 'HKEY_PERFORMANCE_DATA',
     'HKEY_PERFORMANCE_NLSTEXT', 'HKEY_PERFORMANCE_TEXT', 'HKEY_A',
     'HKEY_CURRENT_USER'
    :vartype hive: str or ~azure.mgmt.securityinsight.models.RegistryHive
    :ivar key: The registry key path.
    :vartype key: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'kind': {'required': True},
        'additional_data': {'readonly': True},
        'friendly_name': {'readonly': True},
        'hive': {'readonly': True},
        'key': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'additional_data': {'key': 'properties.additionalData', 'type': '{object}'},
        'friendly_name': {'key': 'properties.friendlyName', 'type': 'str'},
        'hive': {'key': 'properties.hive', 'type': 'str'},
        'key': {'key': 'properties.key', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RegistryKeyEntity, self).__init__(**kwargs)
        self.additional_data = None
        self.friendly_name = None
        self.hive = None
        self.key = None
        self.kind = 'RegistryKey'
