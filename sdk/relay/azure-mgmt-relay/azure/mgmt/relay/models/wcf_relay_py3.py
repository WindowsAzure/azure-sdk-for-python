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

from .resource_py3 import Resource


class WcfRelay(Resource):
    """Description of the WCF relay resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar is_dynamic: Returns true if the relay is dynamic; otherwise, false.
    :vartype is_dynamic: bool
    :ivar created_at: The time the WCF relay was created.
    :vartype created_at: datetime
    :ivar updated_at: The time the namespace was updated.
    :vartype updated_at: datetime
    :ivar listener_count: The number of listeners for this relay. Note that
     min :1 and max:25 are supported.
    :vartype listener_count: int
    :param relay_type: WCF relay type. Possible values include: 'NetTcp',
     'Http'
    :type relay_type: str or ~azure.mgmt.relay.models.Relaytype
    :param requires_client_authorization: Returns true if client authorization
     is needed for this relay; otherwise, false.
    :type requires_client_authorization: bool
    :param requires_transport_security: Returns true if transport security is
     needed for this relay; otherwise, false.
    :type requires_transport_security: bool
    :param user_metadata: The usermetadata is a placeholder to store
     user-defined string data for the WCF Relay endpoint. For example, it can
     be used to store descriptive data, such as list of teams and their contact
     information. Also, user-defined configuration settings can be stored.
    :type user_metadata: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'is_dynamic': {'readonly': True},
        'created_at': {'readonly': True},
        'updated_at': {'readonly': True},
        'listener_count': {'readonly': True, 'maximum': 25, 'minimum': 0},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'is_dynamic': {'key': 'properties.isDynamic', 'type': 'bool'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'listener_count': {'key': 'properties.listenerCount', 'type': 'int'},
        'relay_type': {'key': 'properties.relayType', 'type': 'Relaytype'},
        'requires_client_authorization': {'key': 'properties.requiresClientAuthorization', 'type': 'bool'},
        'requires_transport_security': {'key': 'properties.requiresTransportSecurity', 'type': 'bool'},
        'user_metadata': {'key': 'properties.userMetadata', 'type': 'str'},
    }

    def __init__(self, *, relay_type=None, requires_client_authorization: bool=None, requires_transport_security: bool=None, user_metadata: str=None, **kwargs) -> None:
        super(WcfRelay, self).__init__(**kwargs)
        self.is_dynamic = None
        self.created_at = None
        self.updated_at = None
        self.listener_count = None
        self.relay_type = relay_type
        self.requires_client_authorization = requires_client_authorization
        self.requires_transport_security = requires_transport_security
        self.user_metadata = user_metadata
