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


class CloudApplicationEntity(Entity):
    """Represents a cloud application entity.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar type: Azure resource type
    :vartype type: str
    :ivar name: Azure resource name
    :vartype name: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :ivar friendly_name: The graph item display name which is a short humanly
     readable description of the graph item instance. This property is optional
     and might be system generated.
    :vartype friendly_name: str
    :ivar additional_data: A bag of custom fields that should be part of the
     entity and will be presented to the user.
    :vartype additional_data: dict[str, object]
    :ivar app_id: The technical identifier of the application.
    :vartype app_id: int
    :ivar app_name: The name of the related cloud application.
    :vartype app_name: str
    :ivar instance_name: The user defined instance name of the cloud
     application. It is often used to distinguish between several applications
     of the same type that a customer has.
    :vartype instance_name: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'kind': {'required': True},
        'friendly_name': {'readonly': True},
        'additional_data': {'readonly': True},
        'app_id': {'readonly': True},
        'app_name': {'readonly': True},
        'instance_name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'friendly_name': {'key': 'properties.friendlyName', 'type': 'str'},
        'additional_data': {'key': 'properties.additionalData', 'type': '{object}'},
        'app_id': {'key': 'properties.appId', 'type': 'int'},
        'app_name': {'key': 'properties.appName', 'type': 'str'},
        'instance_name': {'key': 'properties.instanceName', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(CloudApplicationEntity, self).__init__(**kwargs)
        self.friendly_name = None
        self.additional_data = None
        self.app_id = None
        self.app_name = None
        self.instance_name = None
        self.kind = 'CloudApplication'
