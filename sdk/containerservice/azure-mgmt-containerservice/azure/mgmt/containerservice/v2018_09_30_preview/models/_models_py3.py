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
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.CloudErrorBody
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'CloudErrorBody'},
    }

    def __init__(self, *, error=None, **kwargs) -> None:
        super(CloudError, self).__init__(**kwargs)
        self.error = error


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
     list[~azure.mgmt.containerservice.v2018_09_30_preview.models.CloudErrorBody]
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[CloudErrorBody]'},
    }

    def __init__(self, *, code: str=None, message: str=None, target: str=None, details=None, **kwargs) -> None:
        super(CloudErrorBody, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.target = target
        self.details = details


class NetworkProfile(Model):
    """Represents the OpenShift networking configuration.

    :param vnet_cidr: CIDR for the OpenShift Vnet. Default value: "10.0.0.0/8"
     .
    :type vnet_cidr: str
    :param peer_vnet_id: CIDR of the Vnet to peer.
    :type peer_vnet_id: str
    """

    _attribute_map = {
        'vnet_cidr': {'key': 'vnetCidr', 'type': 'str'},
        'peer_vnet_id': {'key': 'peerVnetId', 'type': 'str'},
    }

    def __init__(self, *, vnet_cidr: str="10.0.0.0/8", peer_vnet_id: str=None, **kwargs) -> None:
        super(NetworkProfile, self).__init__(**kwargs)
        self.vnet_cidr = vnet_cidr
        self.peer_vnet_id = peer_vnet_id


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

    def __init__(self, *, location: str, tags=None, **kwargs) -> None:
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = location
        self.tags = tags


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
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.PurchasePlan
    :ivar provisioning_state: The current deployment or provisioning state,
     which only appears in the response.
    :vartype provisioning_state: str
    :param open_shift_version: Required. Version of OpenShift specified when
     creating the cluster.
    :type open_shift_version: str
    :param public_hostname: Optional user-specified FQDN for OpenShift API
     server.
    :type public_hostname: str
    :param fqdn: User-specified FQDN for OpenShift API server loadbalancer
     internal hostname.
    :type fqdn: str
    :param network_profile: Configuration for OpenShift networking.
    :type network_profile:
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.NetworkProfile
    :param router_profiles: Configuration for OpenShift router(s).
    :type router_profiles:
     list[~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftRouterProfile]
    :param master_pool_profile: Configuration for OpenShift master VMs.
    :type master_pool_profile:
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftManagedClusterMasterPoolProfile
    :param agent_pool_profiles: Configuration of OpenShift cluster VMs.
    :type agent_pool_profiles:
     list[~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftManagedClusterAgentPoolProfile]
    :param auth_profile: Configures OpenShift authentication.
    :type auth_profile:
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftManagedClusterAuthProfile
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'open_shift_version': {'required': True},
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
        'public_hostname': {'key': 'properties.publicHostname', 'type': 'str'},
        'fqdn': {'key': 'properties.fqdn', 'type': 'str'},
        'network_profile': {'key': 'properties.networkProfile', 'type': 'NetworkProfile'},
        'router_profiles': {'key': 'properties.routerProfiles', 'type': '[OpenShiftRouterProfile]'},
        'master_pool_profile': {'key': 'properties.masterPoolProfile', 'type': 'OpenShiftManagedClusterMasterPoolProfile'},
        'agent_pool_profiles': {'key': 'properties.agentPoolProfiles', 'type': '[OpenShiftManagedClusterAgentPoolProfile]'},
        'auth_profile': {'key': 'properties.authProfile', 'type': 'OpenShiftManagedClusterAuthProfile'},
    }

    def __init__(self, *, location: str, open_shift_version: str, tags=None, plan=None, public_hostname: str=None, fqdn: str=None, network_profile=None, router_profiles=None, master_pool_profile=None, agent_pool_profiles=None, auth_profile=None, **kwargs) -> None:
        super(OpenShiftManagedCluster, self).__init__(location=location, tags=tags, **kwargs)
        self.plan = plan
        self.provisioning_state = None
        self.open_shift_version = open_shift_version
        self.public_hostname = public_hostname
        self.fqdn = fqdn
        self.network_profile = network_profile
        self.router_profiles = router_profiles
        self.master_pool_profile = master_pool_profile
        self.agent_pool_profiles = agent_pool_profiles
        self.auth_profile = auth_profile


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

    def __init__(self, **kwargs) -> None:
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

    def __init__(self, *, client_id: str=None, secret: str=None, tenant_id: str=None, customer_admin_group_id: str=None, **kwargs) -> None:
        super(OpenShiftManagedClusterAADIdentityProvider, self).__init__(**kwargs)
        self.client_id = client_id
        self.secret = secret
        self.tenant_id = tenant_id
        self.customer_admin_group_id = customer_admin_group_id
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
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftContainerServiceVMSize
    :param subnet_cidr: Subnet CIDR for the peering. Default value:
     "10.0.0.0/24" .
    :type subnet_cidr: str
    :param os_type: OsType to be used to specify os type. Choose from Linux
     and Windows. Default to Linux. Possible values include: 'Linux',
     'Windows'. Default value: "Linux" .
    :type os_type: str or
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OSType
    :param role: Define the role of the AgentPoolProfile. Possible values
     include: 'compute', 'infra'
    :type role: str or
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftAgentPoolProfileRole
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

    def __init__(self, *, name: str, count: int, vm_size, subnet_cidr: str="10.0.0.0/24", os_type="Linux", role=None, **kwargs) -> None:
        super(OpenShiftManagedClusterAgentPoolProfile, self).__init__(**kwargs)
        self.name = name
        self.count = count
        self.vm_size = vm_size
        self.subnet_cidr = subnet_cidr
        self.os_type = os_type
        self.role = role


class OpenShiftManagedClusterAuthProfile(Model):
    """Defines all possible authentication profiles for the OpenShift cluster.

    :param identity_providers: Type of authentication profile to use.
    :type identity_providers:
     list[~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftManagedClusterIdentityProvider]
    """

    _attribute_map = {
        'identity_providers': {'key': 'identityProviders', 'type': '[OpenShiftManagedClusterIdentityProvider]'},
    }

    def __init__(self, *, identity_providers=None, **kwargs) -> None:
        super(OpenShiftManagedClusterAuthProfile, self).__init__(**kwargs)
        self.identity_providers = identity_providers


class OpenShiftManagedClusterIdentityProvider(Model):
    """Defines the configuration of the identity providers to be used in the
    OpenShift cluster.

    :param name: Name of the provider.
    :type name: str
    :param provider: Configuration of the provider.
    :type provider:
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftManagedClusterBaseIdentityProvider
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'OpenShiftManagedClusterBaseIdentityProvider'},
    }

    def __init__(self, *, name: str=None, provider=None, **kwargs) -> None:
        super(OpenShiftManagedClusterIdentityProvider, self).__init__(**kwargs)
        self.name = name
        self.provider = provider


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
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftContainerServiceVMSize
    :param subnet_cidr: Subnet CIDR for the peering.
    :type subnet_cidr: str
    :param os_type: OsType to be used to specify os type. Choose from Linux
     and Windows. Default to Linux. Possible values include: 'Linux',
     'Windows'. Default value: "Linux" .
    :type os_type: str or
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OSType
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

    def __init__(self, *, count: int, vm_size, name: str=None, subnet_cidr: str=None, os_type="Linux", **kwargs) -> None:
        super(OpenShiftManagedClusterMasterPoolProfile, self).__init__(**kwargs)
        self.name = name
        self.count = count
        self.vm_size = vm_size
        self.subnet_cidr = subnet_cidr
        self.os_type = os_type


class OpenShiftRouterProfile(Model):
    """Represents an OpenShift router.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param name: Name of the router profile.
    :type name: str
    :param public_subdomain: DNS subdomain for OpenShift router.
    :type public_subdomain: str
    :ivar fqdn: Auto-allocated FQDN for the OpenShift router.
    :vartype fqdn: str
    """

    _validation = {
        'fqdn': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'public_subdomain': {'key': 'publicSubdomain', 'type': 'str'},
        'fqdn': {'key': 'fqdn', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, public_subdomain: str=None, **kwargs) -> None:
        super(OpenShiftRouterProfile, self).__init__(**kwargs)
        self.name = name
        self.public_subdomain = public_subdomain
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

    def __init__(self, *, name: str=None, product: str=None, promotion_code: str=None, publisher: str=None, **kwargs) -> None:
        super(PurchasePlan, self).__init__(**kwargs)
        self.name = name
        self.product = product
        self.promotion_code = promotion_code
        self.publisher = publisher


class TagsObject(Model):
    """Tags object for patch operations.

    :param tags: Resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, tags=None, **kwargs) -> None:
        super(TagsObject, self).__init__(**kwargs)
        self.tags = tags
