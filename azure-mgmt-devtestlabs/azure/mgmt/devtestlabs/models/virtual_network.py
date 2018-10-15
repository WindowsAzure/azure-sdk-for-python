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

from .resource import Resource


class VirtualNetwork(Resource):
    """A virtual network.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The identifier of the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param location: The location of the resource.
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :param allowed_subnets: The allowed subnets of the virtual network.
    :type allowed_subnets: list[~azure.mgmt.devtestlabs.models.Subnet]
    :param description: The description of the virtual network.
    :type description: str
    :param external_provider_resource_id: The Microsoft.Network resource
     identifier of the virtual network.
    :type external_provider_resource_id: str
    :param external_subnets: The external subnet properties.
    :type external_subnets:
     list[~azure.mgmt.devtestlabs.models.ExternalSubnet]
    :param subnet_overrides: The subnet overrides of the virtual network.
    :type subnet_overrides:
     list[~azure.mgmt.devtestlabs.models.SubnetOverride]
    :ivar created_date: The creation date of the virtual network.
    :vartype created_date: datetime
    :param provisioning_state: The provisioning status of the resource.
    :type provisioning_state: str
    :param unique_identifier: The unique immutable identifier of a resource
     (Guid).
    :type unique_identifier: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created_date': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'allowed_subnets': {'key': 'properties.allowedSubnets', 'type': '[Subnet]'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'external_provider_resource_id': {'key': 'properties.externalProviderResourceId', 'type': 'str'},
        'external_subnets': {'key': 'properties.externalSubnets', 'type': '[ExternalSubnet]'},
        'subnet_overrides': {'key': 'properties.subnetOverrides', 'type': '[SubnetOverride]'},
        'created_date': {'key': 'properties.createdDate', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'unique_identifier': {'key': 'properties.uniqueIdentifier', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(VirtualNetwork, self).__init__(**kwargs)
        self.allowed_subnets = kwargs.get('allowed_subnets', None)
        self.description = kwargs.get('description', None)
        self.external_provider_resource_id = kwargs.get('external_provider_resource_id', None)
        self.external_subnets = kwargs.get('external_subnets', None)
        self.subnet_overrides = kwargs.get('subnet_overrides', None)
        self.created_date = None
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.unique_identifier = kwargs.get('unique_identifier', None)
