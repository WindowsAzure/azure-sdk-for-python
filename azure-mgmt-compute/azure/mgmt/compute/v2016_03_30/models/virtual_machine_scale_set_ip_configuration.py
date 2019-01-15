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
    :param subnet: Required. The subnet.
    :type subnet: ~azure.mgmt.compute.v2016_03_30.models.ApiEntityReference
    :param application_gateway_backend_address_pools: The application gateway
     backend address pools.
    :type application_gateway_backend_address_pools:
     list[~azure.mgmt.compute.v2016_03_30.models.SubResource]
    :param load_balancer_backend_address_pools: The load balancer backend
     address pools.
    :type load_balancer_backend_address_pools:
     list[~azure.mgmt.compute.v2016_03_30.models.SubResource]
    :param load_balancer_inbound_nat_pools: The load balancer inbound nat
     pools.
    :type load_balancer_inbound_nat_pools:
     list[~azure.mgmt.compute.v2016_03_30.models.SubResource]
    """

    _validation = {
        'name': {'required': True},
        'subnet': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'subnet': {'key': 'properties.subnet', 'type': 'ApiEntityReference'},
        'application_gateway_backend_address_pools': {'key': 'properties.applicationGatewayBackendAddressPools', 'type': '[SubResource]'},
        'load_balancer_backend_address_pools': {'key': 'properties.loadBalancerBackendAddressPools', 'type': '[SubResource]'},
        'load_balancer_inbound_nat_pools': {'key': 'properties.loadBalancerInboundNatPools', 'type': '[SubResource]'},
    }

    def __init__(self, **kwargs):
        super(VirtualMachineScaleSetIPConfiguration, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.subnet = kwargs.get('subnet', None)
        self.application_gateway_backend_address_pools = kwargs.get('application_gateway_backend_address_pools', None)
        self.load_balancer_backend_address_pools = kwargs.get('load_balancer_backend_address_pools', None)
        self.load_balancer_inbound_nat_pools = kwargs.get('load_balancer_inbound_nat_pools', None)
