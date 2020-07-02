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

    def __init__(self, **kwargs):
        super(AdminCredentials, self).__init__(**kwargs)
        self.nsxt_username = None
        self.nsxt_password = None
        self.vcenter_username = None
        self.vcenter_password = None


class Circuit(Model):
    """An ExpressRoute Circuit.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar primary_subnet: CIDR of primary subnet
    :vartype primary_subnet: str
    :ivar secondary_subnet: CIDR of secondary subnet
    :vartype secondary_subnet: str
    :ivar express_route_id: Identifier of the ExpressRoute Circuit (Microsoft
     Colo only)
    :vartype express_route_id: str
    :ivar express_route_private_peering_id: ExpressRoute Circuit private
     peering identifier
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
        'express_route_private_peering_id': {'key': 'expressRoutePrivatePeeringID', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Circuit, self).__init__(**kwargs)
        self.primary_subnet = None
        self.secondary_subnet = None
        self.express_route_id = None
        self.express_route_private_peering_id = None


class CloudError(Model):
    """API error response.

    :param error: An error returned by the API
    :type error: ~azure.mgmt.avs.models.ErrorResponse
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorResponse'},
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

    def __init__(self, **kwargs):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class Cluster(Resource):
    """A cluster resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param sku: Required. The cluster SKU
    :type sku: ~azure.mgmt.avs.models.Sku
    :param cluster_size: The cluster size
    :type cluster_size: int
    :ivar cluster_id: The identity
    :vartype cluster_id: int
    :ivar hosts: The hosts
    :vartype hosts: list[str]
    :ivar provisioning_state: The state of the cluster provisioning. Possible
     values include: 'Succeeded', 'Failed', 'Cancelled', 'Deleting', 'Updating'
    :vartype provisioning_state: str or
     ~azure.mgmt.avs.models.ClusterProvisioningState
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'sku': {'required': True},
        'cluster_id': {'readonly': True},
        'hosts': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'cluster_size': {'key': 'properties.clusterSize', 'type': 'int'},
        'cluster_id': {'key': 'properties.clusterId', 'type': 'int'},
        'hosts': {'key': 'properties.hosts', 'type': '[str]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Cluster, self).__init__(**kwargs)
        self.sku = kwargs.get('sku', None)
        self.cluster_size = kwargs.get('cluster_size', None)
        self.cluster_id = None
        self.hosts = None
        self.provisioning_state = None


class ClusterUpdate(Model):
    """An update of a cluster resource.

    :param cluster_size: The cluster size
    :type cluster_size: int
    """

    _attribute_map = {
        'cluster_size': {'key': 'properties.clusterSize', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(ClusterUpdate, self).__init__(**kwargs)
        self.cluster_size = kwargs.get('cluster_size', None)


class ClusterUpdateProperties(Model):
    """The properties of a cluster that may be updated.

    :param cluster_size: The cluster size
    :type cluster_size: int
    """

    _attribute_map = {
        'cluster_size': {'key': 'clusterSize', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(ClusterUpdateProperties, self).__init__(**kwargs)
        self.cluster_size = kwargs.get('cluster_size', None)


class Endpoints(Model):
    """Endpoint addresses.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar nsxt_manager: Endpoint for the NSX-T Data Center manager
    :vartype nsxt_manager: str
    :ivar vcsa: Endpoint for Virtual Center Server Appliance
    :vartype vcsa: str
    :ivar hcx_cloud_manager: Endpoint for the HCX Cloud Manager
    :vartype hcx_cloud_manager: str
    """

    _validation = {
        'nsxt_manager': {'readonly': True},
        'vcsa': {'readonly': True},
        'hcx_cloud_manager': {'readonly': True},
    }

    _attribute_map = {
        'nsxt_manager': {'key': 'nsxtManager', 'type': 'str'},
        'vcsa': {'key': 'vcsa', 'type': 'str'},
        'hcx_cloud_manager': {'key': 'hcxCloudManager', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Endpoints, self).__init__(**kwargs)
        self.nsxt_manager = None
        self.vcsa = None
        self.hcx_cloud_manager = None


class ErrorAdditionalInfo(Model):
    """The resource management error additional info.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar type: The additional info type.
    :vartype type: str
    :ivar info: The additional info.
    :vartype info: object
    """

    _validation = {
        'type': {'readonly': True},
        'info': {'readonly': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'info': {'key': 'info', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(ErrorAdditionalInfo, self).__init__(**kwargs)
        self.type = None
        self.info = None


class ErrorResponse(Model):
    """The resource management error response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: The error code.
    :vartype code: str
    :ivar message: The error message.
    :vartype message: str
    :ivar target: The error target.
    :vartype target: str
    :ivar details: The error details.
    :vartype details: list[~azure.mgmt.avs.models.ErrorResponse]
    :ivar additional_info: The error additional info.
    :vartype additional_info: list[~azure.mgmt.avs.models.ErrorAdditionalInfo]
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'target': {'readonly': True},
        'details': {'readonly': True},
        'additional_info': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorResponse]'},
        'additional_info': {'key': 'additionalInfo', 'type': '[ErrorAdditionalInfo]'},
    }

    def __init__(self, **kwargs):
        super(ErrorResponse, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.target = None
        self.details = None
        self.additional_info = None


class ExpressRouteAuthorization(Resource):
    """ExpressRoute Circuit Authorization.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar provisioning_state: The state of the  ExpressRoute Circuit
     Authorization provisioning. Possible values include: 'Succeeded',
     'Failed', 'Updating'
    :vartype provisioning_state: str or
     ~azure.mgmt.avs.models.ExpressRouteAuthorizationProvisioningState
    :ivar express_route_authorization_id: The ID of the ExpressRoute Circuit
     Authorization
    :vartype express_route_authorization_id: str
    :ivar express_route_authorization_key: The key of the ExpressRoute Circuit
     Authorization
    :vartype express_route_authorization_key: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'express_route_authorization_id': {'readonly': True},
        'express_route_authorization_key': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'express_route_authorization_id': {'key': 'properties.expressRouteAuthorizationId', 'type': 'str'},
        'express_route_authorization_key': {'key': 'properties.expressRouteAuthorizationKey', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ExpressRouteAuthorization, self).__init__(**kwargs)
        self.provisioning_state = None
        self.express_route_authorization_id = None
        self.express_route_authorization_key = None


class HcxEnterpriseSite(Resource):
    """An HCX Enterprise Site resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar activation_key: The activation key
    :vartype activation_key: str
    :ivar status: The status of the HCX Enterprise Site. Possible values
     include: 'Available', 'Consumed', 'Deactivated', 'Deleted'
    :vartype status: str or ~azure.mgmt.avs.models.HcxEnterpriseSiteStatus
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'activation_key': {'readonly': True},
        'status': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'activation_key': {'key': 'properties.activationKey', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(HcxEnterpriseSite, self).__init__(**kwargs)
        self.activation_key = None
        self.status = None


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
    :type ssl: str or ~azure.mgmt.avs.models.SslEnum
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

    def __init__(self, **kwargs):
        super(IdentitySource, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.alias = kwargs.get('alias', None)
        self.domain = kwargs.get('domain', None)
        self.base_user_dn = kwargs.get('base_user_dn', None)
        self.base_group_dn = kwargs.get('base_group_dn', None)
        self.primary_server = kwargs.get('primary_server', None)
        self.secondary_server = kwargs.get('secondary_server', None)
        self.ssl = kwargs.get('ssl', None)
        self.username = kwargs.get('username', None)
        self.password = kwargs.get('password', None)


class ManagementCluster(ClusterUpdateProperties):
    """The properties of a default cluster.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param cluster_size: The cluster size
    :type cluster_size: int
    :ivar cluster_id: The identity
    :vartype cluster_id: int
    :ivar hosts: The hosts
    :vartype hosts: list[str]
    """

    _validation = {
        'cluster_id': {'readonly': True},
        'hosts': {'readonly': True},
    }

    _attribute_map = {
        'cluster_size': {'key': 'clusterSize', 'type': 'int'},
        'cluster_id': {'key': 'clusterId', 'type': 'int'},
        'hosts': {'key': 'hosts', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ManagementCluster, self).__init__(**kwargs)
        self.cluster_id = None
        self.hosts = None


class Operation(Model):
    """A REST API operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Name of the operation being performed on this object
    :vartype name: str
    :ivar display: Contains the localized display information for this
     operation
    :vartype display: ~azure.mgmt.avs.models.OperationDisplay
    """

    _validation = {
        'name': {'readonly': True},
        'display': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(self, **kwargs):
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

    def __init__(self, **kwargs):
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

    def __init__(self, **kwargs):
        super(TrackedResource, self).__init__(**kwargs)
        self.location = kwargs.get('location', None)
        self.tags = kwargs.get('tags', None)


class PrivateCloud(TrackedResource):
    """A private cloud resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

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
    :param sku: Required. The private cloud SKU
    :type sku: ~azure.mgmt.avs.models.Sku
    :param management_cluster: The default cluster used for management
    :type management_cluster: ~azure.mgmt.avs.models.ManagementCluster
    :param internet: Connectivity to internet is enabled or disabled. Possible
     values include: 'Enabled', 'Disabled'
    :type internet: str or ~azure.mgmt.avs.models.InternetEnum
    :param identity_sources: vCenter Single Sign On Identity Sources
    :type identity_sources: list[~azure.mgmt.avs.models.IdentitySource]
    :ivar provisioning_state: The provisioning state. Possible values include:
     'Succeeded', 'Failed', 'Cancelled', 'Pending', 'Building', 'Deleting',
     'Updating'
    :vartype provisioning_state: str or
     ~azure.mgmt.avs.models.PrivateCloudProvisioningState
    :param circuit: An ExpressRoute Circuit
    :type circuit: ~azure.mgmt.avs.models.Circuit
    :ivar endpoints: The endpoints
    :vartype endpoints: ~azure.mgmt.avs.models.Endpoints
    :param network_block: Required. The block of addresses should be unique
     across VNet in your subscription as well as on-premise. Make sure the CIDR
     format is conformed to (A.B.C.D/X) where A,B,C,D are between 0 and 255,
     and X is between 0 and 22
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
    :ivar vcenter_certificate_thumbprint: Thumbprint of the vCenter Server SSL
     certificate
    :vartype vcenter_certificate_thumbprint: str
    :ivar nsxt_certificate_thumbprint: Thumbprint of the NSX-T Manager SSL
     certificate
    :vartype nsxt_certificate_thumbprint: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'sku': {'required': True},
        'provisioning_state': {'readonly': True},
        'endpoints': {'readonly': True},
        'network_block': {'required': True},
        'management_network': {'readonly': True},
        'provisioning_network': {'readonly': True},
        'vmotion_network': {'readonly': True},
        'vcenter_certificate_thumbprint': {'readonly': True},
        'nsxt_certificate_thumbprint': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'management_cluster': {'key': 'properties.managementCluster', 'type': 'ManagementCluster'},
        'internet': {'key': 'properties.internet', 'type': 'str'},
        'identity_sources': {'key': 'properties.identitySources', 'type': '[IdentitySource]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'circuit': {'key': 'properties.circuit', 'type': 'Circuit'},
        'endpoints': {'key': 'properties.endpoints', 'type': 'Endpoints'},
        'network_block': {'key': 'properties.networkBlock', 'type': 'str'},
        'management_network': {'key': 'properties.managementNetwork', 'type': 'str'},
        'provisioning_network': {'key': 'properties.provisioningNetwork', 'type': 'str'},
        'vmotion_network': {'key': 'properties.vmotionNetwork', 'type': 'str'},
        'vcenter_password': {'key': 'properties.vcenterPassword', 'type': 'str'},
        'nsxt_password': {'key': 'properties.nsxtPassword', 'type': 'str'},
        'vcenter_certificate_thumbprint': {'key': 'properties.vcenterCertificateThumbprint', 'type': 'str'},
        'nsxt_certificate_thumbprint': {'key': 'properties.nsxtCertificateThumbprint', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PrivateCloud, self).__init__(**kwargs)
        self.sku = kwargs.get('sku', None)
        self.management_cluster = kwargs.get('management_cluster', None)
        self.internet = kwargs.get('internet', None)
        self.identity_sources = kwargs.get('identity_sources', None)
        self.provisioning_state = None
        self.circuit = kwargs.get('circuit', None)
        self.endpoints = None
        self.network_block = kwargs.get('network_block', None)
        self.management_network = None
        self.provisioning_network = None
        self.vmotion_network = None
        self.vcenter_password = kwargs.get('vcenter_password', None)
        self.nsxt_password = kwargs.get('nsxt_password', None)
        self.vcenter_certificate_thumbprint = None
        self.nsxt_certificate_thumbprint = None


class PrivateCloudUpdate(Model):
    """An update to a private cloud resource.

    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param management_cluster: The default cluster used for management
    :type management_cluster: ~azure.mgmt.avs.models.ManagementCluster
    :param internet: Connectivity to internet is enabled or disabled. Possible
     values include: 'Enabled', 'Disabled'
    :type internet: str or ~azure.mgmt.avs.models.InternetEnum
    :param identity_sources: vCenter Single Sign On Identity Sources
    :type identity_sources: list[~azure.mgmt.avs.models.IdentitySource]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'management_cluster': {'key': 'properties.managementCluster', 'type': 'ManagementCluster'},
        'internet': {'key': 'properties.internet', 'type': 'str'},
        'identity_sources': {'key': 'properties.identitySources', 'type': '[IdentitySource]'},
    }

    def __init__(self, **kwargs):
        super(PrivateCloudUpdate, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.management_cluster = kwargs.get('management_cluster', None)
        self.internet = kwargs.get('internet', None)
        self.identity_sources = kwargs.get('identity_sources', None)


class Quota(Model):
    """Subscription quotas.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar hosts_remaining: Remaining hosts quota by sku type
    :vartype hosts_remaining: dict[str, int]
    :ivar quota_enabled: Host quota is active for current subscription.
     Possible values include: 'Enabled', 'Disabled'
    :vartype quota_enabled: str or ~azure.mgmt.avs.models.QuotaEnabled
    """

    _validation = {
        'hosts_remaining': {'readonly': True},
        'quota_enabled': {'readonly': True},
    }

    _attribute_map = {
        'hosts_remaining': {'key': 'hostsRemaining', 'type': '{int}'},
        'quota_enabled': {'key': 'quotaEnabled', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Quota, self).__init__(**kwargs)
        self.hosts_remaining = None
        self.quota_enabled = None


class Sku(Model):
    """The resource model definition representing SKU.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the SKU.
    :type name: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Sku, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)


class Trial(Model):
    """Subscription trial availability.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar status: Trial status. Possible values include: 'TrialAvailable',
     'TrialUsed', 'TrialDisabled'
    :vartype status: str or ~azure.mgmt.avs.models.TrialStatus
    :ivar available_hosts: Number of trial hosts available
    :vartype available_hosts: int
    """

    _validation = {
        'status': {'readonly': True},
        'available_hosts': {'readonly': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'available_hosts': {'key': 'availableHosts', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(Trial, self).__init__(**kwargs)
        self.status = None
        self.available_hosts = None
