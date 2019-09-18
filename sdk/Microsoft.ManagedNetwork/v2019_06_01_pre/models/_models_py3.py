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

from msrest.serialization import Model
from msrest.exceptions import HttpOperationError


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class ConnectivityCollection(Model):
    """The collection of Connectivity related groups and policies within the
    Managed Network.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar groups: The collection of connectivity related Managed Network
     Groups within the Managed Network
    :vartype groups:
     list[~azure.mgmt.network.v2019_06_01_pre.models.ManagedNetworkGroup]
    :ivar peerings: The collection of Managed Network Peering Policies within
     the Managed Network
    :vartype peerings:
     list[~azure.mgmt.network.v2019_06_01_pre.models.ManagedNetworkPeeringPolicy]
    """

    _validation = {
        'groups': {'readonly': True},
        'peerings': {'readonly': True},
    }

    _attribute_map = {
        'groups': {'key': 'groups', 'type': '[ManagedNetworkGroup]'},
        'peerings': {'key': 'peerings', 'type': '[ManagedNetworkPeeringPolicy]'},
    }

    def __init__(self, **kwargs) -> None:
        super(ConnectivityCollection, self).__init__(**kwargs)
        self.groups = None
        self.peerings = None


class ErrorResponse(Model):
    """The error response that indicates why an operation has failed.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: The error code.
    :vartype code: str
    :ivar message: The error message.
    :vartype message: str
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(ErrorResponse, self).__init__(**kwargs)
        self.code = None
        self.message = None


class ErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorResponseException, self).__init__(deserialize, response, 'ErrorResponse', *args)


class ResourceProperties(Model):
    """Base for resource properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provisioning_state: Provisioning state of the ManagedNetwork
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
     Possible values include: 'Updating', 'Deleting', 'Failed', 'Succeeded'
    :vartype provisioning_state: str or
     ~azure.mgmt.network.v2019_06_01_pre.models.ProvisioningState
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(ResourceProperties, self).__init__(**kwargs)
        self.provisioning_state = None
        self.etag = None


class ManagedNetworkPeeringPolicyProperties(ResourceProperties):
    """Properties of a Managed Network Peering Policy.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar provisioning_state: Provisioning state of the ManagedNetwork
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
     Possible values include: 'Updating', 'Deleting', 'Failed', 'Succeeded'
    :vartype provisioning_state: str or
     ~azure.mgmt.network.v2019_06_01_pre.models.ProvisioningState
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    :param type: Required. Gets or sets the connectivity type of a network
     structure policy. Possible values include: 'HubAndSpokeTopology',
     'MeshTopology'
    :type type: str or ~azure.mgmt.network.v2019_06_01_pre.models.Type
    :param hub: Gets or sets the hub virtual network ID
    :type hub: ~azure.mgmt.network.v2019_06_01_pre.models.ResourceId
    :param spokes: Gets or sets the spokes group IDs
    :type spokes: list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    :param mesh: Gets or sets the mesh group IDs
    :type mesh: list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'etag': {'readonly': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'hub': {'key': 'hub', 'type': 'ResourceId'},
        'spokes': {'key': 'spokes', 'type': '[ResourceId]'},
        'mesh': {'key': 'mesh', 'type': '[ResourceId]'},
    }

    def __init__(self, *, type, hub=None, spokes=None, mesh=None, **kwargs) -> None:
        super(ManagedNetworkPeeringPolicyProperties, self).__init__(**kwargs)
        self.type = type
        self.hub = hub
        self.spokes = spokes
        self.mesh = mesh


class HubAndSpokePeeringPolicyProperties(ManagedNetworkPeeringPolicyProperties):
    """Properties of a Hub and Spoke Peering Policy.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar provisioning_state: Provisioning state of the ManagedNetwork
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
     Possible values include: 'Updating', 'Deleting', 'Failed', 'Succeeded'
    :vartype provisioning_state: str or
     ~azure.mgmt.network.v2019_06_01_pre.models.ProvisioningState
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    :param type: Required. Gets or sets the connectivity type of a network
     structure policy. Possible values include: 'HubAndSpokeTopology',
     'MeshTopology'
    :type type: str or ~azure.mgmt.network.v2019_06_01_pre.models.Type
    :param hub: Gets or sets the hub virtual network ID
    :type hub: ~azure.mgmt.network.v2019_06_01_pre.models.ResourceId
    :param spokes: Gets or sets the spokes group IDs
    :type spokes: list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    :param mesh: Gets or sets the mesh group IDs
    :type mesh: list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'etag': {'readonly': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'hub': {'key': 'hub', 'type': 'ResourceId'},
        'spokes': {'key': 'spokes', 'type': '[ResourceId]'},
        'mesh': {'key': 'mesh', 'type': '[ResourceId]'},
    }

    def __init__(self, *, type, hub=None, spokes=None, mesh=None, **kwargs) -> None:
        super(HubAndSpokePeeringPolicyProperties, self).__init__(type=type, hub=hub, spokes=spokes, mesh=mesh, **kwargs)


class Resource(Model):
    """The general resource model definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param location: The geo-location where the resource lives
    :type location: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, **kwargs) -> None:
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = location


class TrackedResource(Resource):
    """The resource model definition for a ARM tracked top level resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param location: The geo-location where the resource lives
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, location: str=None, tags=None, **kwargs) -> None:
        super(TrackedResource, self).__init__(location=location, **kwargs)
        self.tags = tags


class ManagedNetwork(TrackedResource):
    """The Managed Network resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param location: The geo-location where the resource lives
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :ivar provisioning_state: Provisioning state of the ManagedNetwork
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
     Possible values include: 'Updating', 'Deleting', 'Failed', 'Succeeded'
    :vartype provisioning_state: str or
     ~azure.mgmt.network.v2019_06_01_pre.models.ProvisioningState
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    :param scope: The collection of management groups, subscriptions, virtual
     networks, and subnets by the Managed Network. This is a read-only property
     that is reflective of all ScopeAssignments for this Managed Network
    :type scope: ~azure.mgmt.network.v2019_06_01_pre.models.Scope
    :ivar connectivity: The collection of groups and policies concerned with
     connectivity
    :vartype connectivity:
     ~azure.mgmt.network.v2019_06_01_pre.models.ConnectivityCollection
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'etag': {'readonly': True},
        'connectivity': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'properties.etag', 'type': 'str'},
        'scope': {'key': 'properties.scope', 'type': 'Scope'},
        'connectivity': {'key': 'properties.connectivity', 'type': 'ConnectivityCollection'},
    }

    def __init__(self, *, location: str=None, tags=None, scope=None, **kwargs) -> None:
        super(ManagedNetwork, self).__init__(location=location, tags=tags, **kwargs)
        self.provisioning_state = None
        self.etag = None
        self.scope = scope
        self.connectivity = None


class ProxyResource(Resource):
    """The resource model definition for a ARM proxy resource. It will have
    everything other than required location and tags.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param location: The geo-location where the resource lives
    :type location: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, **kwargs) -> None:
        super(ProxyResource, self).__init__(location=location, **kwargs)


class ManagedNetworkGroup(ProxyResource):
    """The Managed Network Group resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param location: The geo-location where the resource lives
    :type location: str
    :ivar provisioning_state: Provisioning state of the ManagedNetwork
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
     Possible values include: 'Updating', 'Deleting', 'Failed', 'Succeeded'
    :vartype provisioning_state: str or
     ~azure.mgmt.network.v2019_06_01_pre.models.ProvisioningState
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    :param management_groups: The collection of management groups covered by
     the Managed Network
    :type management_groups:
     list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    :param subscriptions: The collection of subscriptions covered by the
     Managed Network
    :type subscriptions:
     list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    :param virtual_networks: The collection of virtual nets covered by the
     Managed Network
    :type virtual_networks:
     list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    :param subnets: The collection of  subnets covered by the Managed Network
    :type subnets: list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    :param kind: Responsibility role under which this Managed Network Group
     will be created. Possible values include: 'Connectivity'
    :type kind: str or ~azure.mgmt.network.v2019_06_01_pre.models.Kind
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'properties.etag', 'type': 'str'},
        'management_groups': {'key': 'properties.managementGroups', 'type': '[ResourceId]'},
        'subscriptions': {'key': 'properties.subscriptions', 'type': '[ResourceId]'},
        'virtual_networks': {'key': 'properties.virtualNetworks', 'type': '[ResourceId]'},
        'subnets': {'key': 'properties.subnets', 'type': '[ResourceId]'},
        'kind': {'key': 'kind', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, management_groups=None, subscriptions=None, virtual_networks=None, subnets=None, kind=None, **kwargs) -> None:
        super(ManagedNetworkGroup, self).__init__(location=location, **kwargs)
        self.provisioning_state = None
        self.etag = None
        self.management_groups = management_groups
        self.subscriptions = subscriptions
        self.virtual_networks = virtual_networks
        self.subnets = subnets
        self.kind = kind


class ManagedNetworkPeeringPolicy(ProxyResource):
    """The Managed Network Peering Policy resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param location: The geo-location where the resource lives
    :type location: str
    :param properties: Gets or sets the properties of a Managed Network Policy
    :type properties:
     ~azure.mgmt.network.v2019_06_01_pre.models.ManagedNetworkPeeringPolicyProperties
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'ManagedNetworkPeeringPolicyProperties'},
    }

    def __init__(self, *, location: str=None, properties=None, **kwargs) -> None:
        super(ManagedNetworkPeeringPolicy, self).__init__(location=location, **kwargs)
        self.properties = properties


class ManagedNetworkUpdate(Model):
    """Update Tags of Managed Network.

    :param tags: Resource tags
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, tags=None, **kwargs) -> None:
        super(ManagedNetworkUpdate, self).__init__(**kwargs)
        self.tags = tags


class MeshPeeringPolicyProperties(ManagedNetworkPeeringPolicyProperties):
    """Properties of a Mesh Peering Policy.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar provisioning_state: Provisioning state of the ManagedNetwork
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
     Possible values include: 'Updating', 'Deleting', 'Failed', 'Succeeded'
    :vartype provisioning_state: str or
     ~azure.mgmt.network.v2019_06_01_pre.models.ProvisioningState
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    :param type: Required. Gets or sets the connectivity type of a network
     structure policy. Possible values include: 'HubAndSpokeTopology',
     'MeshTopology'
    :type type: str or ~azure.mgmt.network.v2019_06_01_pre.models.Type
    :param hub: Gets or sets the hub virtual network ID
    :type hub: ~azure.mgmt.network.v2019_06_01_pre.models.ResourceId
    :param spokes: Gets or sets the spokes group IDs
    :type spokes: list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    :param mesh: Gets or sets the mesh group IDs
    :type mesh: list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'etag': {'readonly': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'hub': {'key': 'hub', 'type': 'ResourceId'},
        'spokes': {'key': 'spokes', 'type': '[ResourceId]'},
        'mesh': {'key': 'mesh', 'type': '[ResourceId]'},
    }

    def __init__(self, *, type, hub=None, spokes=None, mesh=None, **kwargs) -> None:
        super(MeshPeeringPolicyProperties, self).__init__(type=type, hub=hub, spokes=spokes, mesh=mesh, **kwargs)


class Operation(Model):
    """REST API operation.

    :param name: Operation name: {provider}/{resource}/{operation}
    :type name: str
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.network.v2019_06_01_pre.models.OperationDisplay
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(self, *, name: str=None, display=None, **kwargs) -> None:
        super(Operation, self).__init__(**kwargs)
        self.name = name
        self.display = display


class OperationDisplay(Model):
    """The object that represents the operation.

    :param provider: Service provider: Microsoft.ManagedNetwork
    :type provider: str
    :param resource: Resource on which the operation is performed: Profile,
     endpoint, etc.
    :type resource: str
    :param operation: Operation type: Read, write, delete, etc.
    :type operation: str
    """

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
    }

    def __init__(self, *, provider: str=None, resource: str=None, operation: str=None, **kwargs) -> None:
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = provider
        self.resource = resource
        self.operation = operation


class ResourceId(Model):
    """Generic pointer to a resource.

    :param id: Resource Id
    :type id: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, **kwargs) -> None:
        super(ResourceId, self).__init__(**kwargs)
        self.id = id


class Scope(Model):
    """Scope of a Managed Network.

    :param management_groups: The collection of management groups covered by
     the Managed Network
    :type management_groups:
     list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    :param subscriptions: The collection of subscriptions covered by the
     Managed Network
    :type subscriptions:
     list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    :param virtual_networks: The collection of virtual nets covered by the
     Managed Network
    :type virtual_networks:
     list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    :param subnets: The collection of  subnets covered by the Managed Network
    :type subnets: list[~azure.mgmt.network.v2019_06_01_pre.models.ResourceId]
    """

    _attribute_map = {
        'management_groups': {'key': 'managementGroups', 'type': '[ResourceId]'},
        'subscriptions': {'key': 'subscriptions', 'type': '[ResourceId]'},
        'virtual_networks': {'key': 'virtualNetworks', 'type': '[ResourceId]'},
        'subnets': {'key': 'subnets', 'type': '[ResourceId]'},
    }

    def __init__(self, *, management_groups=None, subscriptions=None, virtual_networks=None, subnets=None, **kwargs) -> None:
        super(Scope, self).__init__(**kwargs)
        self.management_groups = management_groups
        self.subscriptions = subscriptions
        self.virtual_networks = virtual_networks
        self.subnets = subnets


class ScopeAssignment(ProxyResource):
    """The Managed Network resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param location: The geo-location where the resource lives
    :type location: str
    :ivar provisioning_state: Provisioning state of the ManagedNetwork
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
     Possible values include: 'Updating', 'Deleting', 'Failed', 'Succeeded'
    :vartype provisioning_state: str or
     ~azure.mgmt.network.v2019_06_01_pre.models.ProvisioningState
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    :param assigned_managed_network: The managed network ID with scope will be
     assigned to.
    :type assigned_managed_network: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'properties.etag', 'type': 'str'},
        'assigned_managed_network': {'key': 'properties.assignedManagedNetwork', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, assigned_managed_network: str=None, **kwargs) -> None:
        super(ScopeAssignment, self).__init__(location=location, **kwargs)
        self.provisioning_state = None
        self.etag = None
        self.assigned_managed_network = assigned_managed_network
