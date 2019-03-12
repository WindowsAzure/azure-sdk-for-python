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

from .sub_resource_py3 import SubResource


class ApplicationGatewayBackendAddressPool(SubResource):
    """Backend Address Pool of an application gateway.

    :param id: Resource ID.
    :type id: str
    :param backend_ip_configurations: Collection of references to IPs defined
     in network interfaces.
    :type backend_ip_configurations:
     list[~azure.mgmt.network.v2018_01_01.models.NetworkInterfaceIPConfiguration]
    :param backend_addresses: Backend addresses
    :type backend_addresses:
     list[~azure.mgmt.network.v2018_01_01.models.ApplicationGatewayBackendAddress]
    :param provisioning_state: Provisioning state of the backend address pool
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :type provisioning_state: str
    :param name: Resource that is unique within a resource group. This name
     can be used to access the resource.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    :param type: Type of the resource.
    :type type: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'backend_ip_configurations': {'key': 'properties.backendIPConfigurations', 'type': '[NetworkInterfaceIPConfiguration]'},
        'backend_addresses': {'key': 'properties.backendAddresses', 'type': '[ApplicationGatewayBackendAddress]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, backend_ip_configurations=None, backend_addresses=None, provisioning_state: str=None, name: str=None, etag: str=None, type: str=None, **kwargs) -> None:
        super(ApplicationGatewayBackendAddressPool, self).__init__(id=id, **kwargs)
        self.backend_ip_configurations = backend_ip_configurations
        self.backend_addresses = backend_addresses
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
        self.type = type
