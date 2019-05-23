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


class ExpressRoutePort(Resource):
    """ExpressRoute Port.

    ExpressRoutePort resource definition.

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
    :param peering_location: The name of the peering location that the
     ExpressRoutePort is mapped to physically.
    :type peering_location: str
    :param bandwidth_in_gbps: Bandwidth of procured ports in Gbps
    :type bandwidth_in_gbps: int
    :ivar provisioned_bandwidth_in_gbps: Aggregate Gbps of associated circuit
     bandwidths.
    :vartype provisioned_bandwidth_in_gbps: float
    :ivar mtu: Maximum transmission unit of the physical port pair(s)
    :vartype mtu: str
    :param encapsulation: Encapsulation method on physical ports. Possible
     values include: 'Dot1Q', 'QinQ'
    :type encapsulation: str or
     ~azure.mgmt.network.v2018_12_01.models.ExpressRoutePortsEncapsulation
    :ivar ether_type: Ether type of the physical port.
    :vartype ether_type: str
    :ivar allocation_date: Date of the physical port allocation to be used in
     Letter of Authorization.
    :vartype allocation_date: str
    :param links: ExpressRouteLink Sub-Resources. The set of physical links of
     the ExpressRoutePort resource
    :type links: list[~azure.mgmt.network.v2018_12_01.models.ExpressRouteLink]
    :ivar circuits: Reference the ExpressRoute circuit(s) that are provisioned
     on this ExpressRoutePort resource.
    :vartype circuits:
     list[~azure.mgmt.network.v2018_12_01.models.SubResource]
    :ivar provisioning_state: The provisioning state of the ExpressRoutePort
     resource. Possible values are: 'Succeeded', 'Updating', 'Deleting', and
     'Failed'.
    :vartype provisioning_state: str
    :param resource_guid: The resource GUID property of the ExpressRoutePort
     resource.
    :type resource_guid: str
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioned_bandwidth_in_gbps': {'readonly': True},
        'mtu': {'readonly': True},
        'ether_type': {'readonly': True},
        'allocation_date': {'readonly': True},
        'circuits': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'peering_location': {'key': 'properties.peeringLocation', 'type': 'str'},
        'bandwidth_in_gbps': {'key': 'properties.bandwidthInGbps', 'type': 'int'},
        'provisioned_bandwidth_in_gbps': {'key': 'properties.provisionedBandwidthInGbps', 'type': 'float'},
        'mtu': {'key': 'properties.mtu', 'type': 'str'},
        'encapsulation': {'key': 'properties.encapsulation', 'type': 'str'},
        'ether_type': {'key': 'properties.etherType', 'type': 'str'},
        'allocation_date': {'key': 'properties.allocationDate', 'type': 'str'},
        'links': {'key': 'properties.links', 'type': '[ExpressRouteLink]'},
        'circuits': {'key': 'properties.circuits', 'type': '[SubResource]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, location: str=None, tags=None, peering_location: str=None, bandwidth_in_gbps: int=None, encapsulation=None, links=None, resource_guid: str=None, **kwargs) -> None:
        super(ExpressRoutePort, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.peering_location = peering_location
        self.bandwidth_in_gbps = bandwidth_in_gbps
        self.provisioned_bandwidth_in_gbps = None
        self.mtu = None
        self.encapsulation = encapsulation
        self.ether_type = None
        self.allocation_date = None
        self.links = links
        self.circuits = None
        self.provisioning_state = None
        self.resource_guid = resource_guid
        self.etag = None
