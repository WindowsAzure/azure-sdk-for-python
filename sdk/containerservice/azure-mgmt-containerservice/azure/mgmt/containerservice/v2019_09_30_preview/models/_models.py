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
    """An error response from the Container service.

    :param error: Details about the error.
    :type error:
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.CloudErrorBody
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'CloudErrorBody'},
    }

    def __init__(self, **kwargs):
        super(CloudError, self).__init__(**kwargs)
        self.error = kwargs.get('error', None)


class CloudErrorException(HttpOperationError):
    """Server responsed with exception of type: 'CloudError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(CloudErrorException, self).__init__(deserialize, response, 'CloudError', *args)


class CloudErrorBody(Model):
    """An error response from the Container service.

    :param code: An identifier for the error. Codes are invariant and are
     intended to be consumed programmatically.
    :type code: str
    :param message: A message describing the error, intended to be suitable
     for display in a user interface.
    :type message: str
    :param target: The target of the particular error. For example, the name
     of the property in error.
    :type target: str
    :param details: A list of additional details about the error.
    :type details:
     list[~azure.mgmt.containerservice.v2019_09_30_preview.models.CloudErrorBody]
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[CloudErrorBody]'},
    }

    def __init__(self, **kwargs):
        super(CloudErrorBody, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)
        self.target = kwargs.get('target', None)
        self.details = kwargs.get('details', None)


class NetworkProfile(Model):
    """Represents the OpenShift networking configuration.

    :param vnet_cidr: CIDR for the OpenShift Vnet. Default value: "10.0.0.0/8"
     .
    :type vnet_cidr: str
    :param peer_vnet_id: CIDR of the Vnet to peer.
    :type peer_vnet_id: str
    :param vnet_id: ID of the Vnet created for OSA cluster.
    :type vnet_id: str
    """

    _attribute_map = {
        'vnet_cidr': {'key': 'vnetCidr', 'type': 'str'},
        'peer_vnet_id': {'key': 'peerVnetId', 'type': 'str'},
        'vnet_id': {'key': 'vnetId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(NetworkProfile, self).__init__(**kwargs)
        self.vnet_cidr = kwargs.get('vnet_cidr', "10.0.0.0/8")
        self.peer_vnet_id = kwargs.get('peer_vnet_id', None)
        self.vnet_id = kwargs.get('vnet_id', None)


class Resource(Model):
    """The Resource model definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Required. Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = kwargs.get('location', None)
        self.tags = kwargs.get('tags', None)


class OpenShiftManagedCluster(Resource):
    """OpenShift Managed cluster.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Required. Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param plan: Define the resource plan as required by ARM for billing
     purposes
    :type plan:
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.PurchasePlan
    :ivar provisioning_state: The current deployment or provisioning state,
     which only appears in the response.
    :vartype provisioning_state: str
    :param open_shift_version: Required. Version of OpenShift specified when
     creating the cluster.
    :type open_shift_version: str
    :ivar cluster_version: Version of OpenShift specified when creating the
     cluster.
    :vartype cluster_version: str
    :ivar public_hostname: Service generated FQDN for OpenShift API server.
    :vartype public_hostname: str
    :ivar fqdn: Service generated FQDN for OpenShift API server loadbalancer
     internal hostname.
    :vartype fqdn: str
    :param network_profile: Configuration for OpenShift networking.
    :type network_profile:
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.NetworkProfile
    :param router_profiles: Configuration for OpenShift router(s).
    :type router_profiles:
     list[~azure.mgmt.containerservice.v2019_09_30_preview.models.OpenShiftRouterProfile]
    :param master_pool_profile: Configuration for OpenShift master VMs.
    :type master_pool_profile:
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.OpenShiftManagedClusterMasterPoolProfile
    :param agent_pool_profiles: Configuration of OpenShift cluster VMs.
    :type agent_pool_profiles:
     list[~azure.mgmt.containerservice.v2019_09_30_preview.models.OpenShiftManagedClusterAgentPoolProfile]
    :param auth_profile: Configures OpenShift authentication.
    :type auth_profile:
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.OpenShiftManagedClusterAuthProfile
    :param monitor_profile: Configures Log Analytics intergration.
    :type monitor_profile:
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.OpenShiftManagedClusterMonitorProfile
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'open_shift_version': {'required': True},
        'cluster_version': {'readonly': True},
        'public_hostname': {'readonly': True},
        'fqdn': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'plan': {'key': 'plan', 'type': 'PurchasePlan'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'open_shift_version': {'key': 'properties.openShiftVersion', 'type': 'str'},
        'cluster_version': {'key': 'properties.clusterVersion', 'type': 'str'},
        'public_hostname': {'key': 'properties.publicHostname', 'type': 'str'},
        'fqdn': {'key': 'properties.fqdn', 'type': 'str'},
        'network_profile': {'key': 'properties.networkProfile', 'type': 'NetworkProfile'},
        'router_profiles': {'key': 'properties.routerProfiles', 'type': '[OpenShiftRouterProfile]'},
        'master_pool_profile': {'key': 'properties.masterPoolProfile', 'type': 'OpenShiftManagedClusterMasterPoolProfile'},
        'agent_pool_profiles': {'key': 'properties.agentPoolProfiles', 'type': '[OpenShiftManagedClusterAgentPoolProfile]'},
        'auth_profile': {'key': 'properties.authProfile', 'type': 'OpenShiftManagedClusterAuthProfile'},
        'monitor_profile': {'key': 'properties.monitorProfile', 'type': 'OpenShiftManagedClusterMonitorProfile'},
    }

    def __init__(self, **kwargs):
        super(OpenShiftManagedCluster, self).__init__(**kwargs)
        self.plan = kwargs.get('plan', None)
        self.provisioning_state = None
        self.open_shift_version = kwargs.get('open_shift_version', None)
        self.cluster_version = None
        self.public_hostname = None
        self.fqdn = None
        self.network_profile = kwargs.get('network_profile', None)
        self.router_profiles = kwargs.get('router_profiles', None)
        self.master_pool_profile = kwargs.get('master_pool_profile', None)
        self.agent_pool_profiles = kwargs.get('agent_pool_profiles', None)
        self.auth_profile = kwargs.get('auth_profile', None)
        self.monitor_profile = kwargs.get('monitor_profile', None)


class OpenShiftManagedClusterBaseIdentityProvider(Model):
    """Structure for any Identity provider.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: OpenShiftManagedClusterAADIdentityProvider

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Constant filled by server.
    :type kind: str
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'kind', 'type': 'str'},
    }

    _subtype_map = {
        'kind': {'AADIdentityProvider': 'OpenShiftManagedClusterAADIdentityProvider'}
    }

    def __init__(self, **kwargs):
        super(OpenShiftManagedClusterBaseIdentityProvider, self).__init__(**kwargs)
        self.kind = None


class OpenShiftManagedClusterAADIdentityProvider(OpenShiftManagedClusterBaseIdentityProvider):
    """Defines the Identity provider for MS AAD.

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Constant filled by server.
    :type kind: str
    :param client_id: The clientId password associated with the provider.
    :type client_id: str
    :param secret: The secret password associated with the provider.
    :type secret: str
    :param tenant_id: The tenantId associated with the provider.
    :type tenant_id: str
    :param customer_admin_group_id: The groupId to be granted cluster admin
     role.
    :type customer_admin_group_id: str
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'kind', 'type': 'str'},
        'client_id': {'key': 'clientId', 'type': 'str'},
        'secret': {'key': 'secret', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'customer_admin_group_id': {'key': 'customerAdminGroupId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OpenShiftManagedClusterAADIdentityProvider, self).__init__(**kwargs)
        self.client_id = kwargs.get('client_id', None)
        self.secret = kwargs.get('secret', None)
        self.tenant_id = kwargs.get('tenant_id', None)
        self.customer_admin_group_id = kwargs.get('customer_admin_group_id', None)
        self.kind = 'AADIdentityProvider'


class OpenShiftManagedClusterAgentPoolProfile(Model):
    """Defines the configuration of the OpenShift cluster VMs.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Unique name of the pool profile in the context of
     the subscription and resource group.
    :type name: str
    :param count: Required. Number of agents (VMs) to host docker containers.
    :type count: int
    :param vm_size: Required. Size of agent VMs. Possible values include:
     'Standard_D2s_v3', 'Standard_D4s_v3', 'Standard_D8s_v3',
     'Standard_D16s_v3', 'Standard_D32s_v3', 'Standard_D64s_v3',
     'Standard_DS4_v2', 'Standard_DS5_v2', 'Standard_F8s_v2',
     'Standard_F16s_v2', 'Standard_F32s_v2', 'Standard_F64s_v2',
     'Standard_F72s_v2', 'Standard_F8s', 'Standard_F16s', 'Standard_E4s_v3',
     'Standard_E8s_v3', 'Standard_E16s_v3', 'Standard_E20s_v3',
     'Standard_E32s_v3', 'Standard_E64s_v3', 'Standard_GS2', 'Standard_GS3',
     'Standard_GS4', 'Standard_GS5', 'Standard_DS12_v2', 'Standard_DS13_v2',
     'Standard_DS14_v2', 'Standard_DS15_v2', 'Standard_L4s', 'Standard_L8s',
     'Standard_L16s', 'Standard_L32s'
    :type vm_size: str or
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.OpenShiftContainerServiceVMSize
    :param subnet_cidr: Subnet CIDR for the peering. Default value:
     "10.0.0.0/24" .
    :type subnet_cidr: str
    :param os_type: OsType to be used to specify os type. Choose from Linux
     and Windows. Default to Linux. Possible values include: 'Linux',
     'Windows'. Default value: "Linux" .
    :type os_type: str or
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.OSType
    :param role: Define the role of the AgentPoolProfile. Possible values
     include: 'compute', 'infra'
    :type role: str or
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.OpenShiftAgentPoolProfileRole
    """

    _validation = {
        'name': {'required': True},
        'count': {'required': True},
        'vm_size': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'count': {'key': 'count', 'type': 'int'},
        'vm_size': {'key': 'vmSize', 'type': 'str'},
        'subnet_cidr': {'key': 'subnetCidr', 'type': 'str'},
        'os_type': {'key': 'osType', 'type': 'str'},
        'role': {'key': 'role', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OpenShiftManagedClusterAgentPoolProfile, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.count = kwargs.get('count', None)
        self.vm_size = kwargs.get('vm_size', None)
        self.subnet_cidr = kwargs.get('subnet_cidr', "10.0.0.0/24")
        self.os_type = kwargs.get('os_type', "Linux")
        self.role = kwargs.get('role', None)


class OpenShiftManagedClusterAuthProfile(Model):
    """Defines all possible authentication profiles for the OpenShift cluster.

    :param identity_providers: Type of authentication profile to use.
    :type identity_providers:
     list[~azure.mgmt.containerservice.v2019_09_30_preview.models.OpenShiftManagedClusterIdentityProvider]
    """

    _attribute_map = {
        'identity_providers': {'key': 'identityProviders', 'type': '[OpenShiftManagedClusterIdentityProvider]'},
    }

    def __init__(self, **kwargs):
        super(OpenShiftManagedClusterAuthProfile, self).__init__(**kwargs)
        self.identity_providers = kwargs.get('identity_providers', None)


class OpenShiftManagedClusterIdentityProvider(Model):
    """Defines the configuration of the identity providers to be used in the
    OpenShift cluster.

    :param name: Name of the provider.
    :type name: str
    :param provider: Configuration of the provider.
    :type provider:
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.OpenShiftManagedClusterBaseIdentityProvider
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'OpenShiftManagedClusterBaseIdentityProvider'},
    }

    def __init__(self, **kwargs):
        super(OpenShiftManagedClusterIdentityProvider, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.provider = kwargs.get('provider', None)


class OpenShiftManagedClusterMasterPoolProfile(Model):
    """OpenShiftManagedClusterMaterPoolProfile contains configuration for
    OpenShift master VMs.

    All required parameters must be populated in order to send to Azure.

    :param name: Unique name of the master pool profile in the context of the
     subscription and resource group.
    :type name: str
    :param count: Required. Number of masters (VMs) to host docker containers.
     The default value is 3.
    :type count: int
    :param vm_size: Required. Size of agent VMs. Possible values include:
     'Standard_D2s_v3', 'Standard_D4s_v3', 'Standard_D8s_v3',
     'Standard_D16s_v3', 'Standard_D32s_v3', 'Standard_D64s_v3',
     'Standard_DS4_v2', 'Standard_DS5_v2', 'Standard_F8s_v2',
     'Standard_F16s_v2', 'Standard_F32s_v2', 'Standard_F64s_v2',
     'Standard_F72s_v2', 'Standard_F8s', 'Standard_F16s', 'Standard_E4s_v3',
     'Standard_E8s_v3', 'Standard_E16s_v3', 'Standard_E20s_v3',
     'Standard_E32s_v3', 'Standard_E64s_v3', 'Standard_GS2', 'Standard_GS3',
     'Standard_GS4', 'Standard_GS5', 'Standard_DS12_v2', 'Standard_DS13_v2',
     'Standard_DS14_v2', 'Standard_DS15_v2', 'Standard_L4s', 'Standard_L8s',
     'Standard_L16s', 'Standard_L32s'
    :type vm_size: str or
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.OpenShiftContainerServiceVMSize
    :param subnet_cidr: Subnet CIDR for the peering.
    :type subnet_cidr: str
    :param os_type: OsType to be used to specify os type. Choose from Linux
     and Windows. Default to Linux. Possible values include: 'Linux',
     'Windows'. Default value: "Linux" .
    :type os_type: str or
     ~azure.mgmt.containerservice.v2019_09_30_preview.models.OSType
    """

    _validation = {
        'count': {'required': True},
        'vm_size': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'count': {'key': 'count', 'type': 'int'},
        'vm_size': {'key': 'vmSize', 'type': 'str'},
        'subnet_cidr': {'key': 'subnetCidr', 'type': 'str'},
        'os_type': {'key': 'osType', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OpenShiftManagedClusterMasterPoolProfile, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.count = kwargs.get('count', None)
        self.vm_size = kwargs.get('vm_size', None)
        self.subnet_cidr = kwargs.get('subnet_cidr', None)
        self.os_type = kwargs.get('os_type', "Linux")


class OpenShiftManagedClusterMonitorProfile(Model):
    """Defines the configuration for Log Analytics integration.

    :param workspace_resource_id: Azure Resource Manager Resource ID for the
     Log Analytics workspace to integrate with.
    :type workspace_resource_id: str
    """

    _attribute_map = {
        'workspace_resource_id': {'key': 'workspaceResourceID', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OpenShiftManagedClusterMonitorProfile, self).__init__(**kwargs)
        self.workspace_resource_id = kwargs.get('workspace_resource_id', None)


class OpenShiftRouterProfile(Model):
    """Represents an OpenShift router.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param name: Name of the router profile.
    :type name: str
    :ivar public_subdomain: DNS subdomain for OpenShift router.
    :vartype public_subdomain: str
    :ivar fqdn: Auto-allocated FQDN for the OpenShift router.
    :vartype fqdn: str
    """

    _validation = {
        'public_subdomain': {'readonly': True},
        'fqdn': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'public_subdomain': {'key': 'publicSubdomain', 'type': 'str'},
        'fqdn': {'key': 'fqdn', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OpenShiftRouterProfile, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.public_subdomain = None
        self.fqdn = None


class PurchasePlan(Model):
    """Used for establishing the purchase context of any 3rd Party artifact
    through MarketPlace.

    :param name: The plan ID.
    :type name: str
    :param product: Specifies the product of the image from the marketplace.
     This is the same value as Offer under the imageReference element.
    :type product: str
    :param promotion_code: The promotion code.
    :type promotion_code: str
    :param publisher: The plan ID.
    :type publisher: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'product': {'key': 'product', 'type': 'str'},
        'promotion_code': {'key': 'promotionCode', 'type': 'str'},
        'publisher': {'key': 'publisher', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PurchasePlan, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.product = kwargs.get('product', None)
        self.promotion_code = kwargs.get('promotion_code', None)
        self.publisher = kwargs.get('publisher', None)


class TagsObject(Model):
    """Tags object for patch operations.

    :param tags: Resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(TagsObject, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
