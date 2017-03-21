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

from .resource import Resource


class HybridConnection(Resource):
    """Hybrid Connection contract. This is used to configure a Hybrid Connection.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :param name: Resource Name.
    :type name: str
    :param kind: Kind of resource.
    :type kind: str
    :param location: Resource Location.
    :type location: str
    :param type: Resource type.
    :type type: str
    :param tags: Resource tags.
    :type tags: dict
    :param service_bus_namespace: The name of the Service Bus namespace.
    :type service_bus_namespace: str
    :param relay_name: The name of the Service Bus relay.
    :type relay_name: str
    :param relay_arm_uri: The ARM URI to the Service Bus relay.
    :type relay_arm_uri: str
    :param hostname: The hostname of the endpoint.
    :type hostname: str
    :param port: The port of the endpoint.
    :type port: int
    :param send_key_name: The name of the Service Bus key which has Send
     permissions. This is used to authenticate to Service Bus.
    :type send_key_name: str
    :param send_key_value: The value of the Service Bus key. This is used to
     authenticate to Service Bus. In ARM this key will not be returned
     normally, use the POST /listKeys API instead.
    :type send_key_value: str
    """

    _validation = {
        'id': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'service_bus_namespace': {'key': 'properties.serviceBusNamespace', 'type': 'str'},
        'relay_name': {'key': 'properties.relayName', 'type': 'str'},
        'relay_arm_uri': {'key': 'properties.relayArmUri', 'type': 'str'},
        'hostname': {'key': 'properties.hostname', 'type': 'str'},
        'port': {'key': 'properties.port', 'type': 'int'},
        'send_key_name': {'key': 'properties.sendKeyName', 'type': 'str'},
        'send_key_value': {'key': 'properties.sendKeyValue', 'type': 'str'},
    }

    def __init__(self, location, name=None, kind=None, type=None, tags=None, service_bus_namespace=None, relay_name=None, relay_arm_uri=None, hostname=None, port=None, send_key_name=None, send_key_value=None):
        super(HybridConnection, self).__init__(name=name, kind=kind, location=location, type=type, tags=tags)
        self.service_bus_namespace = service_bus_namespace
        self.relay_name = relay_name
        self.relay_arm_uri = relay_arm_uri
        self.hostname = hostname
        self.port = port
        self.send_key_name = send_key_name
        self.send_key_value = send_key_value
