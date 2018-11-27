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


class InterfaceEndpoint(Resource):
    """Interface endpoint resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param fqdn: A first-party service's FQDN that is mapped to the private IP
     allocated via this interface endpoint.
    :type fqdn: str
    :param endpoint_service: A reference to the service being brought into the
     virtual network.
    :type endpoint_service:
     ~azure.mgmt.network.v2018_10_01.models.EndpointService
    :param subnet: The ID of the subnet from which the private IP will be
     allocated.
    :type subnet: ~azure.mgmt.network.v2018_10_01.models.Subnet
    :ivar network_interfaces: Gets an array of references to the network
     interfaces created for this interface endpoint.
    :vartype network_interfaces:
     list[~azure.mgmt.network.v2018_10_01.models.NetworkInterface]
    :ivar owner: A read-only property that identifies who created this
     interface endpoint.
    :vartype owner: str
    :ivar provisioning_state: The provisioning state of the interface
     endpoint. Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :vartype provisioning_state: str
    :param etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :type etag: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'network_interfaces': {'readonly': True},
        'owner': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'fqdn': {'key': 'properties.fqdn', 'type': 'str'},
        'endpoint_service': {'key': 'properties.endpointService', 'type': 'EndpointService'},
        'subnet': {'key': 'properties.subnet', 'type': 'Subnet'},
        'network_interfaces': {'key': 'properties.networkInterfaces', 'type': '[NetworkInterface]'},
        'owner': {'key': 'properties.owner', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(InterfaceEndpoint, self).__init__(**kwargs)
        self.fqdn = kwargs.get('fqdn', None)
        self.endpoint_service = kwargs.get('endpoint_service', None)
        self.subnet = kwargs.get('subnet', None)
        self.network_interfaces = None
        self.owner = None
        self.provisioning_state = None
        self.etag = kwargs.get('etag', None)
