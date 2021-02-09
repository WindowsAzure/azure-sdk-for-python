# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Dict, List, Optional, Union

from azure.core.exceptions import HttpResponseError
import msrest.serialization

from ._connected_kubernetes_client_enums import *


class AuthenticationDetails(msrest.serialization.Model):
    """Authentication details of the user.

    All required parameters must be populated in order to send to Azure.

    :param authentication_method: Required. The mode of client authentication. Possible values
     include: "Token".
    :type authentication_method: str or ~azure.mgmt.hybridkubernetes.models.AuthenticationMethod
    :param value: Required. Authentication token value.
    :type value: ~azure.mgmt.hybridkubernetes.models.AuthenticationDetailsValue
    """

    _validation = {
        'authentication_method': {'required': True},
        'value': {'required': True},
    }

    _attribute_map = {
        'authentication_method': {'key': 'authenticationMethod', 'type': 'str'},
        'value': {'key': 'value', 'type': 'AuthenticationDetailsValue'},
    }

    def __init__(
        self,
        *,
        authentication_method: Union[str, "AuthenticationMethod"],
        value: "AuthenticationDetailsValue",
        **kwargs
    ):
        super(AuthenticationDetails, self).__init__(**kwargs)
        self.authentication_method = authentication_method
        self.value = value


class AuthenticationDetailsValue(msrest.serialization.Model):
    """Authentication token value.

    :param token: Authentication token.
    :type token: str
    """

    _attribute_map = {
        'token': {'key': 'token', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        token: Optional[str] = None,
        **kwargs
    ):
        super(AuthenticationDetailsValue, self).__init__(**kwargs)
        self.token = token


class Resource(msrest.serialization.Model):
    """Common fields that are returned in the response for all Azure Resource Manager resources.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
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

    def __init__(
        self,
        **kwargs
    ):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class TrackedResource(Resource):
    """The resource model definition for an Azure Resource Manager tracked top level resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives.
    :type location: str
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
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        location: str,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(TrackedResource, self).__init__(**kwargs)
        self.tags = tags
        self.location = location


class ConnectedCluster(TrackedResource):
    """Represents a connected cluster.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives.
    :type location: str
    :param identity: Required. The identity of the connected cluster.
    :type identity: ~azure.mgmt.hybridkubernetes.models.ConnectedClusterIdentity
    :param agent_public_key_certificate: Required. Base64 encoded public certificate used by the
     agent to do the initial handshake to the backend services in Azure.
    :type agent_public_key_certificate: str
    :param aad_profile: Required. AAD profile of the connected cluster.
    :type aad_profile: ~azure.mgmt.hybridkubernetes.models.ConnectedClusterAADProfile
    :ivar kubernetes_version: The Kubernetes version of the connected cluster resource.
    :vartype kubernetes_version: str
    :ivar total_node_count: Number of nodes present in the connected cluster resource.
    :vartype total_node_count: int
    :ivar total_core_count: Number of CPU cores present in the connected cluster resource.
    :vartype total_core_count: int
    :ivar agent_version: Version of the agent running on the connected cluster resource.
    :vartype agent_version: str
    :param provisioning_state: Provisioning state of the connected cluster resource. Possible
     values include: "Succeeded", "Failed", "Canceled", "Provisioning", "Updating", "Deleting",
     "Accepted".
    :type provisioning_state: str or ~azure.mgmt.hybridkubernetes.models.ProvisioningState
    :param distribution: The Kubernetes distribution running on this connected cluster.
    :type distribution: str
    :param infrastructure: The infrastructure on which the Kubernetes cluster represented by this
     connected cluster is running on.
    :type infrastructure: str
    :ivar offering: Connected cluster offering.
    :vartype offering: str
    :ivar managed_identity_certificate_expiration_time: Expiration time of the managed identity
     certificate.
    :vartype managed_identity_certificate_expiration_time: ~datetime.datetime
    :ivar last_connectivity_time: Time representing the last instance when heart beat was received
     from the cluster.
    :vartype last_connectivity_time: ~datetime.datetime
    :param connectivity_status: Represents the connectivity status of the connected cluster.
     Possible values include: "Connecting", "Connected", "Offline", "Expired".
    :type connectivity_status: str or ~azure.mgmt.hybridkubernetes.models.ConnectivityStatus
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'identity': {'required': True},
        'agent_public_key_certificate': {'required': True},
        'aad_profile': {'required': True},
        'kubernetes_version': {'readonly': True},
        'total_node_count': {'readonly': True},
        'total_core_count': {'readonly': True},
        'agent_version': {'readonly': True},
        'offering': {'readonly': True},
        'managed_identity_certificate_expiration_time': {'readonly': True},
        'last_connectivity_time': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'ConnectedClusterIdentity'},
        'agent_public_key_certificate': {'key': 'properties.agentPublicKeyCertificate', 'type': 'str'},
        'aad_profile': {'key': 'properties.aadProfile', 'type': 'ConnectedClusterAADProfile'},
        'kubernetes_version': {'key': 'properties.kubernetesVersion', 'type': 'str'},
        'total_node_count': {'key': 'properties.totalNodeCount', 'type': 'int'},
        'total_core_count': {'key': 'properties.totalCoreCount', 'type': 'int'},
        'agent_version': {'key': 'properties.agentVersion', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'distribution': {'key': 'properties.distribution', 'type': 'str'},
        'infrastructure': {'key': 'properties.infrastructure', 'type': 'str'},
        'offering': {'key': 'properties.offering', 'type': 'str'},
        'managed_identity_certificate_expiration_time': {'key': 'properties.managedIdentityCertificateExpirationTime', 'type': 'iso-8601'},
        'last_connectivity_time': {'key': 'properties.lastConnectivityTime', 'type': 'iso-8601'},
        'connectivity_status': {'key': 'properties.connectivityStatus', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        location: str,
        identity: "ConnectedClusterIdentity",
        agent_public_key_certificate: str,
        aad_profile: "ConnectedClusterAADProfile",
        tags: Optional[Dict[str, str]] = None,
        provisioning_state: Optional[Union[str, "ProvisioningState"]] = None,
        distribution: Optional[str] = None,
        infrastructure: Optional[str] = None,
        connectivity_status: Optional[Union[str, "ConnectivityStatus"]] = None,
        **kwargs
    ):
        super(ConnectedCluster, self).__init__(tags=tags, location=location, **kwargs)
        self.identity = identity
        self.agent_public_key_certificate = agent_public_key_certificate
        self.aad_profile = aad_profile
        self.kubernetes_version = None
        self.total_node_count = None
        self.total_core_count = None
        self.agent_version = None
        self.provisioning_state = provisioning_state
        self.distribution = distribution
        self.infrastructure = infrastructure
        self.offering = None
        self.managed_identity_certificate_expiration_time = None
        self.last_connectivity_time = None
        self.connectivity_status = connectivity_status


class ConnectedClusterAADProfile(msrest.serialization.Model):
    """AAD profile of the connected cluster.

    All required parameters must be populated in order to send to Azure.

    :param tenant_id: Required. The aad tenant id which is configured on target K8s cluster.
    :type tenant_id: str
    :param client_app_id: Required. The client app id configured on target K8 cluster.
    :type client_app_id: str
    :param server_app_id: Required. The server app id to access AD server.
    :type server_app_id: str
    """

    _validation = {
        'tenant_id': {'required': True},
        'client_app_id': {'required': True},
        'server_app_id': {'required': True},
    }

    _attribute_map = {
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'client_app_id': {'key': 'clientAppId', 'type': 'str'},
        'server_app_id': {'key': 'serverAppId', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        tenant_id: str,
        client_app_id: str,
        server_app_id: str,
        **kwargs
    ):
        super(ConnectedClusterAADProfile, self).__init__(**kwargs)
        self.tenant_id = tenant_id
        self.client_app_id = client_app_id
        self.server_app_id = server_app_id


class ConnectedClusterIdentity(msrest.serialization.Model):
    """Identity for the connected cluster.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar principal_id: The principal id of connected cluster identity. This property will only be
     provided for a system assigned identity.
    :vartype principal_id: str
    :ivar tenant_id: The tenant id associated with the connected cluster. This property will only
     be provided for a system assigned identity.
    :vartype tenant_id: str
    :param type: Required. The type of identity used for the connected cluster. The type
     'SystemAssigned, includes a system created identity. The type 'None' means no identity is
     assigned to the connected cluster. Possible values include: "None", "SystemAssigned".
    :type type: str or ~azure.mgmt.hybridkubernetes.models.ResourceIdentityType
    """

    _validation = {
        'principal_id': {'readonly': True},
        'tenant_id': {'readonly': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        type: Union[str, "ResourceIdentityType"],
        **kwargs
    ):
        super(ConnectedClusterIdentity, self).__init__(**kwargs)
        self.principal_id = None
        self.tenant_id = None
        self.type = type


class ConnectedClusterList(msrest.serialization.Model):
    """The paginated list of connected Clusters.

    :param value: The list of connected clusters.
    :type value: list[~azure.mgmt.hybridkubernetes.models.ConnectedCluster]
    :param next_link: The link to fetch the next page of connected cluster.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ConnectedCluster]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["ConnectedCluster"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(ConnectedClusterList, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class ConnectedClusterPatch(msrest.serialization.Model):
    """Object containing updates for patch operations.

    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param agent_public_key_certificate: Base64 encoded public certificate used by the agent to do
     the initial handshake to the backend services in Azure.
    :type agent_public_key_certificate: str
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'agent_public_key_certificate': {'key': 'properties.agentPublicKeyCertificate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        tags: Optional[Dict[str, str]] = None,
        agent_public_key_certificate: Optional[str] = None,
        **kwargs
    ):
        super(ConnectedClusterPatch, self).__init__(**kwargs)
        self.tags = tags
        self.agent_public_key_certificate = agent_public_key_certificate


class CredentialResult(msrest.serialization.Model):
    """The credential result response.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar name: The name of the credential.
    :vartype name: str
    :ivar value: Base64-encoded Kubernetes configuration file.
    :vartype value: bytearray
    """

    _validation = {
        'name': {'readonly': True},
        'value': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'value': {'key': 'value', 'type': 'bytearray'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CredentialResult, self).__init__(**kwargs)
        self.name = None
        self.value = None


class CredentialResults(msrest.serialization.Model):
    """The list of credential result response.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar hybrid_connection_config: Contains the REP (rendezvous endpoint) and “Sender” access
     token.
    :vartype hybrid_connection_config: ~azure.mgmt.hybridkubernetes.models.HybridConnectionConfig
    :ivar kubeconfigs: Base64-encoded Kubernetes configuration file.
    :vartype kubeconfigs: list[~azure.mgmt.hybridkubernetes.models.CredentialResult]
    """

    _validation = {
        'hybrid_connection_config': {'readonly': True},
        'kubeconfigs': {'readonly': True},
    }

    _attribute_map = {
        'hybrid_connection_config': {'key': 'hybridConnectionConfig', 'type': 'HybridConnectionConfig'},
        'kubeconfigs': {'key': 'kubeconfigs', 'type': '[CredentialResult]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CredentialResults, self).__init__(**kwargs)
        self.hybrid_connection_config = None
        self.kubeconfigs = None


class ErrorAdditionalInfo(msrest.serialization.Model):
    """The resource management error additional info.

    Variables are only populated by the server, and will be ignored when sending a request.

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

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorAdditionalInfo, self).__init__(**kwargs)
        self.type = None
        self.info = None


class ErrorDetail(msrest.serialization.Model):
    """The error detail.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar code: The error code.
    :vartype code: str
    :ivar message: The error message.
    :vartype message: str
    :ivar target: The error target.
    :vartype target: str
    :ivar details: The error details.
    :vartype details: list[~azure.mgmt.hybridkubernetes.models.ErrorDetail]
    :ivar additional_info: The error additional info.
    :vartype additional_info: list[~azure.mgmt.hybridkubernetes.models.ErrorAdditionalInfo]
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
        'details': {'key': 'details', 'type': '[ErrorDetail]'},
        'additional_info': {'key': 'additionalInfo', 'type': '[ErrorAdditionalInfo]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorDetail, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.target = None
        self.details = None
        self.additional_info = None


class ErrorResponse(msrest.serialization.Model):
    """Common error response for all Azure Resource Manager APIs to return error details for failed operations. (This also follows the OData error response format.).

    :param error: The error object.
    :type error: ~azure.mgmt.hybridkubernetes.models.ErrorDetail
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorDetail'},
    }

    def __init__(
        self,
        *,
        error: Optional["ErrorDetail"] = None,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = error


class HybridConnectionConfig(msrest.serialization.Model):
    """Contains the REP (rendezvous endpoint) and “Sender” access token.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar expiration_time: Timestamp when this token will be expired.
    :vartype expiration_time: long
    :ivar hybrid_connection_name: Name of the connection.
    :vartype hybrid_connection_name: str
    :ivar relay: Name of the relay.
    :vartype relay: str
    :ivar token: Sender access token.
    :vartype token: str
    """

    _validation = {
        'expiration_time': {'readonly': True},
        'hybrid_connection_name': {'readonly': True},
        'relay': {'readonly': True},
        'token': {'readonly': True},
    }

    _attribute_map = {
        'expiration_time': {'key': 'expirationTime', 'type': 'long'},
        'hybrid_connection_name': {'key': 'hybridConnectionName', 'type': 'str'},
        'relay': {'key': 'relay', 'type': 'str'},
        'token': {'key': 'token', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(HybridConnectionConfig, self).__init__(**kwargs)
        self.expiration_time = None
        self.hybrid_connection_name = None
        self.relay = None
        self.token = None


class Operation(msrest.serialization.Model):
    """The Connected cluster API operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar name: Operation name: {Microsoft.Kubernetes}/{resource}/{operation}.
    :vartype name: str
    :ivar display: The object that represents the operation.
    :vartype display: ~azure.mgmt.hybridkubernetes.models.OperationDisplay
    """

    _validation = {
        'name': {'readonly': True},
        'display': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Operation, self).__init__(**kwargs)
        self.name = None
        self.display = None


class OperationDisplay(msrest.serialization.Model):
    """The object that represents the operation.

    :param provider: Service provider: Microsoft.connectedClusters.
    :type provider: str
    :param resource: Connected Cluster Resource on which the operation is performed.
    :type resource: str
    :param operation: Operation type: Read, write, delete, etc.
    :type operation: str
    :param description: Description of the operation.
    :type description: str
    """

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        provider: Optional[str] = None,
        resource: Optional[str] = None,
        operation: Optional[str] = None,
        description: Optional[str] = None,
        **kwargs
    ):
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = provider
        self.resource = resource
        self.operation = operation
        self.description = description


class OperationList(msrest.serialization.Model):
    """The paginated list of connected cluster API operations.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: The list of connected cluster API operations.
    :vartype value: list[~azure.mgmt.hybridkubernetes.models.Operation]
    :param next_link: The link to fetch the next page of connected cluster API operations.
    :type next_link: str
    """

    _validation = {
        'value': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Operation]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(OperationList, self).__init__(**kwargs)
        self.value = None
        self.next_link = next_link
