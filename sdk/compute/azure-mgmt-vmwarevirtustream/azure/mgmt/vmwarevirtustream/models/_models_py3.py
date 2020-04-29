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


class AdminCredentials(Model):
    """Administrative credentials for accessing vCenter and NSX-T.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar nsxt_username: NSX-T Manager username
    :vartype nsxt_username: str
    :ivar nsxt_password: NSX-T Manager password
    :vartype nsxt_password: str
    :ivar vcenter_username: vCenter admin username
    :vartype vcenter_username: str
    :ivar vcenter_password: vCenter admin password
    :vartype vcenter_password: str
    """

    _validation = {
        'nsxt_username': {'readonly': True},
        'nsxt_password': {'readonly': True},
        'vcenter_username': {'readonly': True},
        'vcenter_password': {'readonly': True},
    }

    _attribute_map = {
        'nsxt_username': {'key': 'nsxtUsername', 'type': 'str'},
        'nsxt_password': {'key': 'nsxtPassword', 'type': 'str'},
        'vcenter_username': {'key': 'vcenterUsername', 'type': 'str'},
        'vcenter_password': {'key': 'vcenterPassword', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(AdminCredentials, self).__init__(**kwargs)
        self.nsxt_username = None
        self.nsxt_password = None
        self.vcenter_username = None
        self.vcenter_password = None


class ApiError(Model):
    """API error response.

    :param error: An error returned by the API
    :type error: ~azure.mgmt.vmwarevirtustream.models.ApiErrorBase
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ApiErrorBase'},
    }

    def __init__(self, *, error=None, **kwargs) -> None:
        super(ApiError, self).__init__(**kwargs)
        self.error = error


class ApiErrorException(HttpOperationError):
    """Server responsed with exception of type: 'ApiError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ApiErrorException, self).__init__(deserialize, response, 'ApiError', *args)


class ApiErrorBase(Model):
    """Api error.

    :param code: Error code
    :type code: str
    :param message: Error message
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, *, code: str=None, message: str=None, **kwargs) -> None:
        super(ApiErrorBase, self).__init__(**kwargs)
        self.code = code
        self.message = message


class Circuit(Model):
    """An ExpressRoute Circuit.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar primary_subnet: CIDR of primary subnet
    :vartype primary_subnet: str
    :ivar secondary_subnet: CIDR of secondary subnet
    :vartype secondary_subnet: str
    :ivar express_route_id: Identifier of the ExpressRoute (Microsoft Colo
     only)
    :vartype express_route_id: str
    :param authorizations: Authorizations for the ExpressRoute (Microsoft Colo
     only)
    :type authorizations:
     list[~azure.mgmt.vmwarevirtustream.models.ExpressRouteAuthorization]
    :ivar express_route_private_peering_id: ExpressRoute private peering
     identifier
    :vartype express_route_private_peering_id: str
    """

    _validation = {
        'primary_subnet': {'readonly': True},
        'secondary_subnet': {'readonly': True},
        'express_route_id': {'readonly': True},
        'express_route_private_peering_id': {'readonly': True},
    }

    _attribute_map = {
        'primary_subnet': {'key': 'primarySubnet', 'type': 'str'},
        'secondary_subnet': {'key': 'secondarySubnet', 'type': 'str'},
        'express_route_id': {'key': 'expressRouteID', 'type': 'str'},
        'authorizations': {'key': 'authorizations', 'type': '[ExpressRouteAuthorization]'},
        'express_route_private_peering_id': {'key': 'expressRoutePrivatePeeringID', 'type': 'str'},
    }

    def __init__(self, *, authorizations=None, **kwargs) -> None:
        super(Circuit, self).__init__(**kwargs)
        self.primary_subnet = None
        self.secondary_subnet = None
        self.express_route_id = None
        self.authorizations = authorizations
        self.express_route_private_peering_id = None


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class Resource(Model):
    """The core properties of ARM resources.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
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
    }

    def __init__(self, **kwargs) -> None:
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class Cluster(Resource):
    """A cluster resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param properties: The properties of a cluster resource
    :type properties: ~azure.mgmt.vmwarevirtustream.models.ClusterProperties
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
        'properties': {'key': 'properties', 'type': 'ClusterProperties'},
    }

    def __init__(self, *, properties=None, **kwargs) -> None:
        super(Cluster, self).__init__(**kwargs)
        self.properties = properties


class DefaultClusterProperties(Model):
    """The properties of a default cluster.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar cluster_id: The identity
    :vartype cluster_id: int
    :param cluster_size: The cluster size
    :type cluster_size: int
    :ivar hosts: The hosts
    :vartype hosts: list[str]
    """

    _validation = {
        'cluster_id': {'readonly': True},
        'hosts': {'readonly': True},
    }

    _attribute_map = {
        'cluster_id': {'key': 'clusterId', 'type': 'int'},
        'cluster_size': {'key': 'clusterSize', 'type': 'int'},
        'hosts': {'key': 'hosts', 'type': '[str]'},
    }

    def __init__(self, *, cluster_size: int=None, **kwargs) -> None:
        super(DefaultClusterProperties, self).__init__(**kwargs)
        self.cluster_id = None
        self.cluster_size = cluster_size
        self.hosts = None


class ClusterProperties(DefaultClusterProperties):
    """The properties of a cluster.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar cluster_id: The identity
    :vartype cluster_id: int
    :param cluster_size: The cluster size
    :type cluster_size: int
    :ivar hosts: The hosts
    :vartype hosts: list[str]
    :ivar provisioning_state: The state of the cluster provisioning. Possible
     values include: 'Succeeded', 'Failed', 'Cancelled', 'Updating'
    :vartype provisioning_state: str or
     ~azure.mgmt.vmwarevirtustream.models.ClusterProvisioningState
    """

    _validation = {
        'cluster_id': {'readonly': True},
        'hosts': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'cluster_id': {'key': 'clusterId', 'type': 'int'},
        'cluster_size': {'key': 'clusterSize', 'type': 'int'},
        'hosts': {'key': 'hosts', 'type': '[str]'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
    }

    def __init__(self, *, cluster_size: int=None, **kwargs) -> None:
        super(ClusterProperties, self).__init__(cluster_size=cluster_size, **kwargs)
        self.provisioning_state = None


class Endpoints(Model):
    """Endpoint addresses.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar nsxt_manager: Endpoint for the NSX-T Data Center manager
    :vartype nsxt_manager: str
    :ivar vcsa: Endpoint for Virtual Center Server Appliance
    :vartype vcsa: str
    """

    _validation = {
        'nsxt_manager': {'readonly': True},
        'vcsa': {'readonly': True},
    }

    _attribute_map = {
        'nsxt_manager': {'key': 'nsxtManager', 'type': 'str'},
        'vcsa': {'key': 'vcsa', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(Endpoints, self).__init__(**kwargs)
        self.nsxt_manager = None
        self.vcsa = None


class ExpressRouteAuthorization(Model):
    """Authorization for an ExpressRoute.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param name: The name of the ExpressRoute
    :type name: str
    :ivar id: The ID of the ExpressRoute
    :vartype id: str
    :ivar key: The key of the ExpressRoute
    :vartype key: str
    """

    _validation = {
        'id': {'readonly': True},
        'key': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'key': {'key': 'key', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, **kwargs) -> None:
        super(ExpressRouteAuthorization, self).__init__(**kwargs)
        self.name = name
        self.id = None
        self.key = None


class IdentitySource(Model):
    """vCenter Single Sign On Identity Source.

    :param name: The name of the identity source
    :type name: str
    :param alias: The domain's NetBIOS name
    :type alias: str
    :param domain: The domain's dns name
    :type domain: str
    :param base_user_dn: The base distinguished name for users
    :type base_user_dn: str
    :param base_group_dn: The base distinguished name for groups
    :type base_group_dn: str
    :param primary_server: Primary server URL
    :type primary_server: str
    :param secondary_server: Secondary server URL
    :type secondary_server: str
    :param ssl: Protect LDAP communication using SSL certificate (LDAPS).
     Possible values include: 'Enabled', 'Disabled'
    :type ssl: str or ~azure.mgmt.vmwarevirtustream.models.SslEnum
    :param username: The ID of an Active Directory user with a minimum of
     read-only access to Base DN for users and group
    :type username: str
    :param password: The password of the Active Directory user with a minimum
     of read-only access to Base DN for users and groups.
    :type password: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'alias': {'key': 'alias', 'type': 'str'},
        'domain': {'key': 'domain', 'type': 'str'},
        'base_user_dn': {'key': 'baseUserDN', 'type': 'str'},
        'base_group_dn': {'key': 'baseGroupDN', 'type': 'str'},
        'primary_server': {'key': 'primaryServer', 'type': 'str'},
        'secondary_server': {'key': 'secondaryServer', 'type': 'str'},
        'ssl': {'key': 'ssl', 'type': 'str'},
        'username': {'key': 'username', 'type': 'str'},
        'password': {'key': 'password', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, alias: str=None, domain: str=None, base_user_dn: str=None, base_group_dn: str=None, primary_server: str=None, secondary_server: str=None, ssl=None, username: str=None, password: str=None, **kwargs) -> None:
        super(IdentitySource, self).__init__(**kwargs)
        self.name = name
        self.alias = alias
        self.domain = domain
        self.base_user_dn = base_user_dn
        self.base_group_dn = base_group_dn
        self.primary_server = primary_server
        self.secondary_server = secondary_server
        self.ssl = ssl
        self.username = username
        self.password = password


class Operation(Model):
    """A REST API operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Name of the operation being performed on this object
    :vartype name: str
    :ivar display: Contains the localized display information for this
     operation
    :vartype display: ~azure.mgmt.vmwarevirtustream.models.OperationDisplay
    """

    _validation = {
        'name': {'readonly': True},
        'display': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(self, **kwargs) -> None:
        super(Operation, self).__init__(**kwargs)
        self.name = None
        self.display = None


class OperationDisplay(Model):
    """Contains the localized display information for this operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provider: Localized friendly form of the resource provider name
    :vartype provider: str
    :ivar resource: Localized friendly form of the resource type related to
     this operation
    :vartype resource: str
    :ivar operation: Localized friendly name for the operation
    :vartype operation: str
    :ivar description: Localized friendly description for the operation
    :vartype description: str
    """

    _validation = {
        'provider': {'readonly': True},
        'resource': {'readonly': True},
        'operation': {'readonly': True},
        'description': {'readonly': True},
    }

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = None
        self.resource = None
        self.operation = None
        self.description = None


class TrackedResource(Resource):
    """The resource model definition for a ARM tracked top level resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location
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
        super(TrackedResource, self).__init__(**kwargs)
        self.location = location
        self.tags = tags


class PrivateCloud(TrackedResource):
    """A private cloud resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param properties: The properties of a private cloud resource
    :type properties:
     ~azure.mgmt.vmwarevirtustream.models.PrivateCloudProperties
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
        'properties': {'key': 'properties', 'type': 'PrivateCloudProperties'},
    }

    def __init__(self, *, location: str=None, tags=None, properties=None, **kwargs) -> None:
        super(PrivateCloud, self).__init__(location=location, tags=tags, **kwargs)
        self.properties = properties


class PrivateCloudProperties(Model):
    """The properties of a private cloud resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provisioning_state: The provisioning state. Possible values include:
     'Succeeded', 'Failed', 'Cancelled', 'Pending', 'Building', 'Updating'
    :vartype provisioning_state: str or
     ~azure.mgmt.vmwarevirtustream.models.PrivateCloudProvisioningState
    :param circuit: An ExpressRoute Circuit
    :type circuit: ~azure.mgmt.vmwarevirtustream.models.Circuit
    :param cluster: The default cluster used for management
    :type cluster:
     ~azure.mgmt.vmwarevirtustream.models.DefaultClusterProperties
    :ivar clusters: The clusters
    :vartype clusters: list[str]
    :ivar endpoints: The endpoints
    :vartype endpoints: ~azure.mgmt.vmwarevirtustream.models.Endpoints
    :param internet: Connectivity to internet is enabled or disabled. Possible
     values include: 'Enabled', 'Disabled'
    :type internet: str or ~azure.mgmt.vmwarevirtustream.models.InternetEnum
    :param identity_sources: vCenter Single Sign On Identity Sources
    :type identity_sources:
     list[~azure.mgmt.vmwarevirtustream.models.IdentitySource]
    :param network_block: The block of addresses should be unique across VNet
     in your subscription as well as on-premise. Make sure the CIDR format is
     conformed to (A.B.C.D/X) where A,B,C,D are between 0 and 255, and X is
     between 0 and 22
    :type network_block: str
    :ivar management_network: Network used to access vCenter Server and NSX-T
     Manager
    :vartype management_network: str
    :ivar provisioning_network: Used for virtual machine cold migration,
     cloning, and snapshot migration
    :vartype provisioning_network: str
    :ivar vmotion_network: Used for live migration of virtual machines
    :vartype vmotion_network: str
    :param vcenter_password: Optionally, set the vCenter admin password when
     the private cloud is created
    :type vcenter_password: str
    :param nsxt_password: Optionally, set the NSX-T Manager password when the
     private cloud is created
    :type nsxt_password: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'clusters': {'readonly': True},
        'endpoints': {'readonly': True},
        'management_network': {'readonly': True},
        'provisioning_network': {'readonly': True},
        'vmotion_network': {'readonly': True},
    }

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'circuit': {'key': 'circuit', 'type': 'Circuit'},
        'cluster': {'key': 'cluster', 'type': 'DefaultClusterProperties'},
        'clusters': {'key': 'clusters', 'type': '[str]'},
        'endpoints': {'key': 'endpoints', 'type': 'Endpoints'},
        'internet': {'key': 'internet', 'type': 'str'},
        'identity_sources': {'key': 'identitySources', 'type': '[IdentitySource]'},
        'network_block': {'key': 'networkBlock', 'type': 'str'},
        'management_network': {'key': 'managementNetwork', 'type': 'str'},
        'provisioning_network': {'key': 'provisioningNetwork', 'type': 'str'},
        'vmotion_network': {'key': 'vmotionNetwork', 'type': 'str'},
        'vcenter_password': {'key': 'vcenterPassword', 'type': 'str'},
        'nsxt_password': {'key': 'nsxtPassword', 'type': 'str'},
    }

    def __init__(self, *, circuit=None, cluster=None, internet=None, identity_sources=None, network_block: str=None, vcenter_password: str=None, nsxt_password: str=None, **kwargs) -> None:
        super(PrivateCloudProperties, self).__init__(**kwargs)
        self.provisioning_state = None
        self.circuit = circuit
        self.cluster = cluster
        self.clusters = None
        self.endpoints = None
        self.internet = internet
        self.identity_sources = identity_sources
        self.network_block = network_block
        self.management_network = None
        self.provisioning_network = None
        self.vmotion_network = None
        self.vcenter_password = vcenter_password
        self.nsxt_password = nsxt_password


class QuotaGet(Model):
    """Subscription quotas.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar hosts_remaining: Remaining hosts quota by sku type
    :vartype hosts_remaining: dict[str, int]
    :ivar quota_enabled: Host quota is active for current subscription
    :vartype quota_enabled: bool
    """

    _validation = {
        'hosts_remaining': {'readonly': True},
        'quota_enabled': {'readonly': True},
    }

    _attribute_map = {
        'hosts_remaining': {'key': 'hostsRemaining', 'type': '{int}'},
        'quota_enabled': {'key': 'quotaEnabled', 'type': 'bool'},
    }

    def __init__(self, **kwargs) -> None:
        super(QuotaGet, self).__init__(**kwargs)
        self.hosts_remaining = None
        self.quota_enabled = None
