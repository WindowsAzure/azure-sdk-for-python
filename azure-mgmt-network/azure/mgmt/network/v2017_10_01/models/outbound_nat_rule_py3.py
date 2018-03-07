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

from .sub_resource import SubResource


class OutboundNatRule(SubResource):
    """Outbound NAT pool of the load balancer.

    All required parameters must be populated in order to send to Azure.

    :param id: Resource ID.
    :type id: str
    :param allocated_outbound_ports: The number of outbound ports to be used
     for NAT.
    :type allocated_outbound_ports: int
    :param frontend_ip_configurations: The Frontend IP addresses of the load
     balancer.
    :type frontend_ip_configurations:
     list[~azure.mgmt.network.v2017_10_01.models.SubResource]
    :param backend_address_pool: Required. A reference to a pool of DIPs.
     Outbound traffic is randomly load balanced across IPs in the backend IPs.
    :type backend_address_pool:
     ~azure.mgmt.network.v2017_10_01.models.SubResource
    :param provisioning_state: Gets the provisioning state of the PublicIP
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :type provisioning_state: str
    :param name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    """

    _validation = {
        'backend_address_pool': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'allocated_outbound_ports': {'key': 'properties.allocatedOutboundPorts', 'type': 'int'},
        'frontend_ip_configurations': {'key': 'properties.frontendIPConfigurations', 'type': '[SubResource]'},
        'backend_address_pool': {'key': 'properties.backendAddressPool', 'type': 'SubResource'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, backend_address_pool, id: str=None, allocated_outbound_ports: int=None, frontend_ip_configurations=None, provisioning_state: str=None, name: str=None, etag: str=None, **kwargs) -> None:
        super(OutboundNatRule, self).__init__(id=id, **kwargs)
        self.allocated_outbound_ports = allocated_outbound_ports
        self.frontend_ip_configurations = frontend_ip_configurations
        self.backend_address_pool = backend_address_pool
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
