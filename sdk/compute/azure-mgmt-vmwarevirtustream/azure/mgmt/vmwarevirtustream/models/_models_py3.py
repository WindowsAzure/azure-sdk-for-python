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
    """AdminCredentials.

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

    :param error:
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
    """Circuit.

    :param primary_subnet: CIDR of primary subnet
    :type primary_subnet: str
    :param secondary_subnet: CIDR of secondary subnet
    :type secondary_subnet: str
    :param express_route_id: Identifier of the ExpressRoute (Microsoft Colo
     only)
    :type express_route_id: str
    :param authorizations: Authorizations for the ExpressRoute (Microsoft Colo
     only)
    :type authorizations:
     list[~azure.mgmt.vmwarevirtustream.models.ExpressRouteAuthorization]
    :param express_route_private_peering_id: ExpressRoute private peering
     identifier
    :type express_route_private_peering_id: str
    """

    _attribute_map = {
        'primary_subnet': {'key': 'primarySubnet', 'type': 'str'},
        'secondary_subnet': {'key': 'secondarySubnet', 'type': 'str'},
        'express_route_id': {'key': 'expressRouteID', 'type': 'str'},
        'authorizations': {'key': 'authorizations', 'type': '[ExpressRouteAuthorization]'},
        'express_route_private_peering_id': {'key': 'expressRoutePrivatePeeringID', 'type': 'str'},
    }

    def __init__(self, *, primary_subnet: str=None, secondary_subnet: str=None, express_route_id: str=None, authorizations=None, express_route_private_peering_id: str=None, **kwargs) -> None:
        super(Circuit, self).__init__(**kwargs)
        self.primary_subnet = primary_subnet
        self.secondary_subnet = secondary_subnet
        self.express_route_id = express_route_id
        self.authorizations = authorizations
        self.express_route_private_peering_id = express_route_private_peering_id


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
    """Cluster.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar cluster_id:
    :vartype cluster_id: int
    :param cluster_size:
    :type cluster_size: int
    :ivar hosts:
    :vartype hosts: list[str]
    :ivar provisioning_state: Possible values include: 'Succeeded', 'Failed',
     'Cancelled', 'Updating'
    :vartype provisioning_state: str or
     ~azure.mgmt.vmwarevirtustream.models.ClusterProvisioningState
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'cluster_id': {'readonly': True},
        'cluster_size': {'maximum': 16, 'minimum': 3},
        'hosts': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'cluster_id': {'key': 'properties.clusterId', 'type': 'int'},
        'cluster_size': {'key': 'properties.clusterSize', 'type': 'int'},
        'hosts': {'key': 'properties.hosts', 'type': '[str]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, *, cluster_size: int=None, **kwargs) -> None:
        super(Cluster, self).__init__(**kwargs)
        self.cluster_id = None
        self.cluster_size = cluster_size
        self.hosts = None
        self.provisioning_state = None


class DefaultClusterProperties(Model):
    """DefaultClusterProperties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar cluster_id:
    :vartype cluster_id: int
    :param cluster_size:
    :type cluster_size: int
    :ivar hosts:
    :vartype hosts: list[str]
    """

    _validation = {
        'cluster_id': {'readonly': True},
        'cluster_size': {'maximum': 16, 'minimum': 3},
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


class Endpoints(Model):
    """Endpoints.

    :param nsxt_manager:
    :type nsxt_manager: str
    :param vcsa:
    :type vcsa: str
    """

    _attribute_map = {
        'nsxt_manager': {'key': 'nsxtManager', 'type': 'str'},
        'vcsa': {'key': 'vcsa', 'type': 'str'},
    }

    def __init__(self, *, nsxt_manager: str=None, vcsa: str=None, **kwargs) -> None:
        super(Endpoints, self).__init__(**kwargs)
        self.nsxt_manager = nsxt_manager
        self.vcsa = vcsa


class ExpressRouteAuthorization(Model):
    """ExpressRouteAuthorization.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param name:
    :type name: str
    :ivar id:
    :vartype id: str
    :ivar key:
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
    """IdentitySource.

    :param name:
    :type name: str
    :param alias:
    :type alias: str
    :param domain:
    :type domain: str
    :param base_user_dn:
    :type base_user_dn: str
    :param base_group_dn:
    :type base_group_dn: str
    :param primary_server:
    :type primary_server: str
    :param secondary_server:
    :type secondary_server: str
    :param ssl: Possible values include: 'Enabled', 'Disabled'
    :type ssl: str or ~azure.mgmt.vmwarevirtustream.models.SslEnum
    :param username:
    :type username: str
    :param password:
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
    """PrivateCloud.

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
    :ivar provisioning_state: Possible values include: 'Succeeded', 'Failed',
     'Cancelled', 'Pending', 'Building', 'Updating'
    :vartype provisioning_state: str or
     ~azure.mgmt.vmwarevirtustream.models.PrivateCloudProvisioningState
    :param circuit:
    :type circuit: ~azure.mgmt.vmwarevirtustream.models.Circuit
    :param cluster:
    :type cluster:
     ~azure.mgmt.vmwarevirtustream.models.DefaultClusterProperties
    :ivar clusters:
    :vartype clusters: list[str]
    :param endpoints:
    :type endpoints: ~azure.mgmt.vmwarevirtustream.models.Endpoints
    :param internet: Possible values include: 'Enabled', 'Disabled'
    :type internet: str or ~azure.mgmt.vmwarevirtustream.models.InternetEnum
    :ivar identity_sources:
    :vartype identity_sources:
     list[~azure.mgmt.vmwarevirtustream.models.IdentitySource]
    :param network_block:
    :type network_block: str
    :ivar management_network:
    :vartype management_network: str
    :ivar provisioning_network:
    :vartype provisioning_network: str
    :ivar vmotion_network:
    :vartype vmotion_network: str
    :param vcenter_password: Optionally, set the vCenter admin password when
     the private cloud is created
    :type vcenter_password: str
    :param nsxt_password: Optionally, set the NSX-T Manager password when the
     private cloud is created
    :type nsxt_password: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'clusters': {'readonly': True},
        'identity_sources': {'readonly': True},
        'management_network': {'readonly': True},
        'provisioning_network': {'readonly': True},
        'vmotion_network': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'circuit': {'key': 'properties.circuit', 'type': 'Circuit'},
        'cluster': {'key': 'properties.cluster', 'type': 'DefaultClusterProperties'},
        'clusters': {'key': 'properties.clusters', 'type': '[str]'},
        'endpoints': {'key': 'properties.endpoints', 'type': 'Endpoints'},
        'internet': {'key': 'properties.internet', 'type': 'str'},
        'identity_sources': {'key': 'properties.identitySources', 'type': '[IdentitySource]'},
        'network_block': {'key': 'properties.networkBlock', 'type': 'str'},
        'management_network': {'key': 'properties.managementNetwork', 'type': 'str'},
        'provisioning_network': {'key': 'properties.provisioningNetwork', 'type': 'str'},
        'vmotion_network': {'key': 'properties.vmotionNetwork', 'type': 'str'},
        'vcenter_password': {'key': 'properties.vcenterPassword', 'type': 'str'},
        'nsxt_password': {'key': 'properties.nsxtPassword', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, tags=None, circuit=None, cluster=None, endpoints=None, internet=None, network_block: str=None, vcenter_password: str=None, nsxt_password: str=None, **kwargs) -> None:
        super(PrivateCloud, self).__init__(location=location, tags=tags, **kwargs)
        self.provisioning_state = None
        self.circuit = circuit
        self.cluster = cluster
        self.clusters = None
        self.endpoints = endpoints
        self.internet = internet
        self.identity_sources = None
        self.network_block = network_block
        self.management_network = None
        self.provisioning_network = None
        self.vmotion_network = None
        self.vcenter_password = vcenter_password
        self.nsxt_password = nsxt_password
