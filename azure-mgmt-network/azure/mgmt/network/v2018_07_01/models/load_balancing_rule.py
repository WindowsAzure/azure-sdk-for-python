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
    """A load balancing rule for a load balancer.

    All required parameters must be populated in order to send to Azure.

    :param id: Resource ID.
    :type id: str
    :param frontend_ip_configuration: A reference to frontend IP addresses.
    :type frontend_ip_configuration:
     ~azure.mgmt.network.v2018_07_01.models.SubResource
    :param backend_address_pool: A reference to a pool of DIPs. Inbound
     traffic is randomly load balanced across IPs in the backend IPs.
    :type backend_address_pool:
     ~azure.mgmt.network.v2018_07_01.models.SubResource
    :param probe: The reference of the load balancer probe used by the load
     balancing rule.
    :type probe: ~azure.mgmt.network.v2018_07_01.models.SubResource
    :param protocol: Required. Possible values include: 'Udp', 'Tcp', 'All'
    :type protocol: str or
     ~azure.mgmt.network.v2018_07_01.models.TransportProtocol
    :param load_distribution: The load distribution policy for this rule.
     Possible values are 'Default', 'SourceIP', and 'SourceIPProtocol'.
     Possible values include: 'Default', 'SourceIP', 'SourceIPProtocol'
    :type load_distribution: str or
     ~azure.mgmt.network.v2018_07_01.models.LoadDistribution
    :param frontend_port: Required. The port for the external endpoint. Port
     numbers for each rule must be unique within the Load Balancer. Acceptable
     values are between 0 and 65534. Note that value 0 enables "Any Port"
    :type frontend_port: int
    :param backend_port: The port used for internal connections on the
     endpoint. Acceptable values are between 0 and 65535. Note that value 0
     enables "Any Port"
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
    :param enable_tcp_reset: Receive bidirectional TCP Reset on TCP flow idle
     timeout or unexpected connection termination. This element is only used
     when the protocol is set to TCP.
    :type enable_tcp_reset: bool
    :param disable_outbound_snat: Configures SNAT for the VMs in the backend
     pool to use the publicIP address specified in the frontend of the load
     balancing rule.
    :type disable_outbound_snat: bool
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
        'enable_tcp_reset': {'key': 'properties.enableTcpReset', 'type': 'bool'},
        'disable_outbound_snat': {'key': 'properties.disableOutboundSnat', 'type': 'bool'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(LoadBalancingRule, self).__init__(**kwargs)
        self.frontend_ip_configuration = kwargs.get('frontend_ip_configuration', None)
        self.backend_address_pool = kwargs.get('backend_address_pool', None)
        self.probe = kwargs.get('probe', None)
        self.protocol = kwargs.get('protocol', None)
        self.load_distribution = kwargs.get('load_distribution', None)
        self.frontend_port = kwargs.get('frontend_port', None)
        self.backend_port = kwargs.get('backend_port', None)
        self.idle_timeout_in_minutes = kwargs.get('idle_timeout_in_minutes', None)
        self.enable_floating_ip = kwargs.get('enable_floating_ip', None)
        self.enable_tcp_reset = kwargs.get('enable_tcp_reset', None)
        self.disable_outbound_snat = kwargs.get('disable_outbound_snat', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.name = kwargs.get('name', None)
        self.etag = kwargs.get('etag', None)
