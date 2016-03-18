# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .sub_resource import SubResource


class OutboundNatRule(SubResource):
    """
    Outbound NAT pool of the loadbalancer

    :param id: Resource Id
    :type id: str
    :param allocated_outbound_ports: Gets or sets the number of outbound
     ports to be used for SNAT
    :type allocated_outbound_ports: int
    :param frontend_ip_configurations: Gets or sets Frontend IP addresses of
     the load balancer
    :type frontend_ip_configurations: list of :class:`SubResource
     <azure.mgmt.network.models.SubResource>`
    :param backend_address_pool: Gets or sets a reference to a pool of DIPs.
     Outbound traffic is randomly load balanced across IPs in the backend IPs
    :type backend_address_pool: :class:`SubResource
     <azure.mgmt.network.models.SubResource>`
    :param provisioning_state: Gets or sets Provisioning state of the
     PublicIP resource Updating/Deleting/Failed
    :type provisioning_state: str
    :param name: Gets name of the resource that is unique within a resource
     group. This name can be used to access the resource
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated
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

    def __init__(self, backend_address_pool, id=None, allocated_outbound_ports=None, frontend_ip_configurations=None, provisioning_state=None, name=None, etag=None, **kwargs):
        super(OutboundNatRule, self).__init__(id=id, **kwargs)
        self.allocated_outbound_ports = allocated_outbound_ports
        self.frontend_ip_configurations = frontend_ip_configurations
        self.backend_address_pool = backend_address_pool
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
