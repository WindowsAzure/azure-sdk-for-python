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


class LoadBalancingRule(SubResource):
    """
    Rules of the load balancer

    :param id: Resource Id
    :type id: str
    :param frontend_ip_configuration: Gets or sets a reference to frontend IP
     Addresses
    :type frontend_ip_configuration: :class:`SubResource
     <networkmanagementclient.models.SubResource>`
    :param backend_address_pool: Gets or sets  a reference to a pool of DIPs.
     Inbound traffic is randomly load balanced across IPs in the backend IPs
    :type backend_address_pool: :class:`SubResource
     <networkmanagementclient.models.SubResource>`
    :param probe: Gets or sets the reference of the load balancer probe used
     by the Load Balancing rule.
    :type probe: :class:`SubResource
     <networkmanagementclient.models.SubResource>`
    :param protocol: Gets or sets the transport protocol for the external
     endpoint. Possible values are Udp or Tcp. Possible values include:
     'Udp', 'Tcp'
    :type protocol: str
    :param load_distribution: Gets or sets the load distribution policy for
     this rule. Possible values include: 'Default', 'SourceIP',
     'SourceIPProtocol'
    :type load_distribution: str
    :param frontend_port: Gets or sets the port for the external endpoint.
     You can specify any port number you choose, but the port numbers
     specified for each role in the service must be unique. Possible values
     range between 1 and 65535, inclusive
    :type frontend_port: int
    :param backend_port: Gets or sets a port used for internal connections on
     the endpoint. The localPort attribute maps the eternal port of the
     endpoint to an internal port on a role. This is useful in scenarios
     where a role must communicate to an internal compotnent on a port that
     is different from the one that is exposed externally. If not specified,
     the value of localPort is the same as the port attribute. Set the value
     of localPort to '*' to automatically assign an unallocated port that is
     discoverable using the runtime API
    :type backend_port: int
    :param idle_timeout_in_minutes: Gets or sets the timeout for the Tcp idle
     connection. The value can be set between 4 and 30 minutes. The default
     value is 4 minutes. This emlement is only used when the protocol is set
     to Tcp
    :type idle_timeout_in_minutes: int
    :param enable_floating_ip: Configures a virtual machine's endpoint for
     the floating IP capability required to configure a SQL AlwaysOn
     availability Group. This setting is required when using the SQL Always
     ON availability Groups in SQL server. This setting can't be changed
     after you create the endpoint
    :type enable_floating_ip: bool
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
        'protocol': {'required': True},
        'frontend_port': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'frontend_ip_configuration': {'key': 'properties.frontendIPConfiguration', 'type': 'SubResource'},
        'backend_address_pool': {'key': 'properties.backendAddressPool', 'type': 'SubResource'},
        'probe': {'key': 'properties.probe', 'type': 'SubResource'},
        'protocol': {'key': 'properties.protocol', 'type': 'TransportProtocol'},
        'load_distribution': {'key': 'properties.loadDistribution', 'type': 'LoadDistribution'},
        'frontend_port': {'key': 'properties.frontendPort', 'type': 'int'},
        'backend_port': {'key': 'properties.backendPort', 'type': 'int'},
        'idle_timeout_in_minutes': {'key': 'properties.idleTimeoutInMinutes', 'type': 'int'},
        'enable_floating_ip': {'key': 'properties.enableFloatingIP', 'type': 'bool'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, protocol, frontend_port, id=None, frontend_ip_configuration=None, backend_address_pool=None, probe=None, load_distribution=None, backend_port=None, idle_timeout_in_minutes=None, enable_floating_ip=None, provisioning_state=None, name=None, etag=None):
        super(LoadBalancingRule, self).__init__(id=id)
        self.frontend_ip_configuration = frontend_ip_configuration
        self.backend_address_pool = backend_address_pool
        self.probe = probe
        self.protocol = protocol
        self.load_distribution = load_distribution
        self.frontend_port = frontend_port
        self.backend_port = backend_port
        self.idle_timeout_in_minutes = idle_timeout_in_minutes
        self.enable_floating_ip = enable_floating_ip
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
