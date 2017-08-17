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


class ApplicationGatewayFrontendIPConfiguration(SubResource):
    """Frontend IP configuration of an application gateway.

    :param id: Resource Identifier.
    :type id: str
    :param private_ip_address: PrivateIPAddress of the network interface IP
     Configuration.
    :type private_ip_address: str
    :param private_ip_allocation_method: PrivateIP allocation method. Possible
     values are: 'Static' and 'Dynamic'. Possible values include: 'Static',
     'Dynamic'
    :type private_ip_allocation_method: str or :class:`IPAllocationMethod
     <azure.mgmt.network.v2015_06_15.models.IPAllocationMethod>`
    :param subnet: Reference of the subnet resource.
    :type subnet: :class:`SubResource
     <azure.mgmt.network.v2015_06_15.models.SubResource>`
    :param public_ip_address: Reference of the PublicIP resource.
    :type public_ip_address: :class:`SubResource
     <azure.mgmt.network.v2015_06_15.models.SubResource>`
    :param provisioning_state: Provisioning state of the public IP resource.
     Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :type provisioning_state: str
    :param name: Name of the resource that is unique within a resource group.
     This name can be used to access the resource.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'private_ip_address': {'key': 'properties.privateIPAddress', 'type': 'str'},
        'private_ip_allocation_method': {'key': 'properties.privateIPAllocationMethod', 'type': 'str'},
        'subnet': {'key': 'properties.subnet', 'type': 'SubResource'},
        'public_ip_address': {'key': 'properties.publicIPAddress', 'type': 'SubResource'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, id=None, private_ip_address=None, private_ip_allocation_method=None, subnet=None, public_ip_address=None, provisioning_state=None, name=None, etag=None):
        super(ApplicationGatewayFrontendIPConfiguration, self).__init__(id=id)
        self.private_ip_address = private_ip_address
        self.private_ip_allocation_method = private_ip_allocation_method
        self.subnet = subnet
        self.public_ip_address = public_ip_address
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
