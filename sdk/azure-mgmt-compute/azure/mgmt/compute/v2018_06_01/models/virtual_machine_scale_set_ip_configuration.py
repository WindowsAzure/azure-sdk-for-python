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


class VirtualMachineScaleSetIPConfiguration(SubResource):
    """Describes a virtual machine scale set network profile's IP configuration.

    All required parameters must be populated in order to send to Azure.

    :param id: Resource Id
    :type id: str
    :param name: Required. The IP configuration name.
    :type name: str
    :param subnet: Specifies the identifier of the subnet.
    :type subnet: ~azure.mgmt.compute.v2018_06_01.models.ApiEntityReference
    :param primary: Specifies the primary network interface in case the
     virtual machine has more than 1 network interface.
    :type primary: bool
    :param public_ip_address_configuration: The publicIPAddressConfiguration.
    :type public_ip_address_configuration:
     ~azure.mgmt.compute.v2018_06_01.models.VirtualMachineScaleSetPublicIPAddressConfiguration
    :param private_ip_address_version: Available from Api-Version 2017-03-30
     onwards, it represents whether the specific ipconfiguration is IPv4 or
     IPv6. Default is taken as IPv4.  Possible values are: 'IPv4' and 'IPv6'.
     Possible values include: 'IPv4', 'IPv6'
    :type private_ip_address_version: str or
     ~azure.mgmt.compute.v2018_06_01.models.IPVersion
    :param application_gateway_backend_address_pools: Specifies an array of
     references to backend address pools of application gateways. A scale set
     can reference backend address pools of multiple application gateways.
     Multiple scale sets cannot use the same application gateway.
    :type application_gateway_backend_address_pools:
     list[~azure.mgmt.compute.v2018_06_01.models.SubResource]
    :param application_security_groups: Specifies an array of references to
     application security group.
    :type application_security_groups:
     list[~azure.mgmt.compute.v2018_06_01.models.SubResource]
    :param load_balancer_backend_address_pools: Specifies an array of
     references to backend address pools of load balancers. A scale set can
     reference backend address pools of one public and one internal load
     balancer. Multiple scale sets cannot use the same load balancer.
    :type load_balancer_backend_address_pools:
     list[~azure.mgmt.compute.v2018_06_01.models.SubResource]
    :param load_balancer_inbound_nat_pools: Specifies an array of references
     to inbound Nat pools of the load balancers. A scale set can reference
     inbound nat pools of one public and one internal load balancer. Multiple
     scale sets cannot use the same load balancer
    :type load_balancer_inbound_nat_pools:
     list[~azure.mgmt.compute.v2018_06_01.models.SubResource]
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'subnet': {'key': 'properties.subnet', 'type': 'ApiEntityReference'},
        'primary': {'key': 'properties.primary', 'type': 'bool'},
        'public_ip_address_configuration': {'key': 'properties.publicIPAddressConfiguration', 'type': 'VirtualMachineScaleSetPublicIPAddressConfiguration'},
        'private_ip_address_version': {'key': 'properties.privateIPAddressVersion', 'type': 'str'},
        'application_gateway_backend_address_pools': {'key': 'properties.applicationGatewayBackendAddressPools', 'type': '[SubResource]'},
        'application_security_groups': {'key': 'properties.applicationSecurityGroups', 'type': '[SubResource]'},
        'load_balancer_backend_address_pools': {'key': 'properties.loadBalancerBackendAddressPools', 'type': '[SubResource]'},
        'load_balancer_inbound_nat_pools': {'key': 'properties.loadBalancerInboundNatPools', 'type': '[SubResource]'},
    }

    def __init__(self, **kwargs):
        super(VirtualMachineScaleSetIPConfiguration, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.subnet = kwargs.get('subnet', None)
        self.primary = kwargs.get('primary', None)
        self.public_ip_address_configuration = kwargs.get('public_ip_address_configuration', None)
        self.private_ip_address_version = kwargs.get('private_ip_address_version', None)
        self.application_gateway_backend_address_pools = kwargs.get('application_gateway_backend_address_pools', None)
        self.application_security_groups = kwargs.get('application_security_groups', None)
        self.load_balancer_backend_address_pools = kwargs.get('load_balancer_backend_address_pools', None)
        self.load_balancer_inbound_nat_pools = kwargs.get('load_balancer_inbound_nat_pools', None)
