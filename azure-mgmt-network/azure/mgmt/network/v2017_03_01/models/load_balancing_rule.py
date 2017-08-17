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


class LoadBalancingRule(SubResource):
    """A loag balancing rule for a load balancer.

    :param id: Resource ID.
    :type id: str
    :param frontend_ip_configuration: A reference to frontend IP addresses.
    :type frontend_ip_configuration: :class:`SubResource
     <azure.mgmt.network.v2017_03_01.models.SubResource>`
    :param backend_address_pool: A reference to a pool of DIPs. Inbound
     traffic is randomly load balanced across IPs in the backend IPs.
    :type backend_address_pool: :class:`SubResource
     <azure.mgmt.network.v2017_03_01.models.SubResource>`
    :param probe: The reference of the load balancer probe used by the load
     balancing rule.
    :type probe: :class:`SubResource
     <azure.mgmt.network.v2017_03_01.models.SubResource>`
    :param protocol: The transport protocol for the external endpoint.
     Possible values are 'Udp' or 'Tcp'. Possible values include: 'Udp', 'Tcp'
    :type protocol: str or :class:`TransportProtocol
     <azure.mgmt.network.v2017_03_01.models.TransportProtocol>`
    :param load_distribution: The load distribution policy for this rule.
     Possible values are 'Default', 'SourceIP', and 'SourceIPProtocol'.
     Possible values include: 'Default', 'SourceIP', 'SourceIPProtocol'
    :type load_distribution: str or :class:`LoadDistribution
     <azure.mgmt.network.v2017_03_01.models.LoadDistribution>`
    :param frontend_port: The port for the external endpoint. Port numbers for
     each Rule must be unique within the Load Balancer. Acceptable values are
     between 1 and 65534.
    :type frontend_port: int
    :param backend_port: The port used for internal connections on the
     endpoint. Acceptable values are between 1 and 65535.
    :type backend_port: int
    :param idle_timeout_in_minutes: The timeout for the TCP idle connection.
     The value can be set between 4 and 30 minutes. The default value is 4
     minutes. This element is only used when the protocol is set to TCP.
    :type idle_timeout_in_minutes: int
    :param enable_floating_ip: Configures a virtual machine's endpoint for the
     floating IP capability required to configure a SQL AlwaysOn Availability
     Group. This setting is required when using the SQL AlwaysOn Availability
     Groups in SQL server. This setting can't be changed after you create the
     endpoint.
    :type enable_floating_ip: bool
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
        'protocol': {'required': True},
        'frontend_port': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'frontend_ip_configuration': {'key': 'properties.frontendIPConfiguration', 'type': 'SubResource'},
        'backend_address_pool': {'key': 'properties.backendAddressPool', 'type': 'SubResource'},
        'probe': {'key': 'properties.probe', 'type': 'SubResource'},
        'protocol': {'key': 'properties.protocol', 'type': 'str'},
        'load_distribution': {'key': 'properties.loadDistribution', 'type': 'str'},
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
