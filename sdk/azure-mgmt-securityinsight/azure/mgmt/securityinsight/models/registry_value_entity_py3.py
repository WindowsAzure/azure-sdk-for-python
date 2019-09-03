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

from .entity_py3 import Entity


class RegistryValueEntity(Entity):
    """Represents a registry value entity.

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
    :ivar key_entity_id: The registry key entity id.
    :vartype key_entity_id: str
    :ivar value_data: String formatted representation of the value data.
    :vartype value_data: str
    :ivar value_name: The registry value name.
    :vartype value_name: str
    :ivar value_type: Specifies the data types to use when storing values in
     the registry, or identifies the data type of a value in the registry.
     Possible values include: 'None', 'Unknown', 'String', 'ExpandString',
     'Binary', 'DWord', 'MultiString', 'QWord'
    :vartype value_type: str or
     ~azure.mgmt.securityinsight.models.RegistryValueKind
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'kind': {'required': True},
        'additional_data': {'readonly': True},
        'friendly_name': {'readonly': True},
        'key_entity_id': {'readonly': True},
        'value_data': {'readonly': True},
        'value_name': {'readonly': True},
        'value_type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'additional_data': {'key': 'properties.additionalData', 'type': '{object}'},
        'friendly_name': {'key': 'properties.friendlyName', 'type': 'str'},
        'key_entity_id': {'key': 'properties.keyEntityId', 'type': 'str'},
        'value_data': {'key': 'properties.valueData', 'type': 'str'},
        'value_name': {'key': 'properties.valueName', 'type': 'str'},
        'value_type': {'key': 'properties.valueType', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(RegistryValueEntity, self).__init__(**kwargs)
        self.additional_data = None
        self.friendly_name = None
        self.key_entity_id = None
        self.value_data = None
        self.value_name = None
        self.value_type = None
        self.kind = 'RegistryValue'
