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


class InboundNatRule(SubResource):
    """
    Inbound NAT rule of the loadbalancer

    :param id: Resource Id
    :type id: str
    :param frontend_ip_configuration: Gets or sets a reference to frontend IP
     Addresses
    :type frontend_ip_configuration: :class:`SubResource
     <azure.mgmt.network.models.SubResource>`
    :param backend_ip_configuration: Gets or sets a reference to a private ip
     address defined on a NetworkInterface of a VM. Traffic sent to
     frontendPort of each of the frontendIPConfigurations is forwarded to the
     backed IP
    :type backend_ip_configuration: :class:`NetworkInterfaceIPConfiguration
     <azure.mgmt.network.models.NetworkInterfaceIPConfiguration>`
    :param protocol: Gets or sets the transport potocol for the external
     endpoint. Possible values are Udp or Tcp. Possible values include:
     'Udp', 'Tcp'
    :type protocol: str
    :param frontend_port: Gets or sets the port for the external endpoint.
     You can spcify any port number you choose, but the port numbers
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

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'frontend_ip_configuration': {'key': 'properties.frontendIPConfiguration', 'type': 'SubResource'},
        'backend_ip_configuration': {'key': 'properties.backendIPConfiguration', 'type': 'NetworkInterfaceIPConfiguration'},
        'protocol': {'key': 'properties.protocol', 'type': 'TransportProtocol'},
        'frontend_port': {'key': 'properties.frontendPort', 'type': 'int'},
        'backend_port': {'key': 'properties.backendPort', 'type': 'int'},
        'idle_timeout_in_minutes': {'key': 'properties.idleTimeoutInMinutes', 'type': 'int'},
        'enable_floating_ip': {'key': 'properties.enableFloatingIP', 'type': 'bool'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, id=None, frontend_ip_configuration=None, backend_ip_configuration=None, protocol=None, frontend_port=None, backend_port=None, idle_timeout_in_minutes=None, enable_floating_ip=None, provisioning_state=None, name=None, etag=None, **kwargs):
        super(InboundNatRule, self).__init__(id=id, **kwargs)
        self.frontend_ip_configuration = frontend_ip_configuration
        self.backend_ip_configuration = backend_ip_configuration
        self.protocol = protocol
        self.frontend_port = frontend_port
        self.backend_port = backend_port
        self.idle_timeout_in_minutes = idle_timeout_in_minutes
        self.enable_floating_ip = enable_floating_ip
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
