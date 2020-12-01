# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import msrest.serialization


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
    """The resource model definition for an Azure Resource Manager tracked top level resource which has 'tags' and a 'location'.

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
        **kwargs
    ):
        super(TrackedResource, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.location = kwargs['location']


class AttestationProvider(TrackedResource):
    """Attestation service response message.

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
    :ivar system_data: The system metadata relating to this resource.
    :vartype system_data: ~azure.mgmt.attestation.models.SystemData
    :param trust_model: Trust model for the attestation provider.
    :type trust_model: str
    :param status: Status of attestation service. Possible values include: "Ready", "NotReady",
     "Error".
    :type status: str or ~azure.mgmt.attestation.models.AttestationServiceStatus
    :param attest_uri: Gets the uri of attestation service.
    :type attest_uri: str
    :ivar private_endpoint_connections: List of private endpoint connections associated with the
     attestation provider.
    :vartype private_endpoint_connections:
     list[~azure.mgmt.attestation.models.PrivateEndpointConnectionItem]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'system_data': {'readonly': True},
        'private_endpoint_connections': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'system_data': {'key': 'systemData', 'type': 'SystemData'},
        'trust_model': {'key': 'properties.trustModel', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'attest_uri': {'key': 'properties.attestUri', 'type': 'str'},
        'private_endpoint_connections': {'key': 'properties.privateEndpointConnections', 'type': '[PrivateEndpointConnectionItem]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AttestationProvider, self).__init__(**kwargs)
        self.system_data = None
        self.trust_model = kwargs.get('trust_model', None)
        self.status = kwargs.get('status', None)
        self.attest_uri = kwargs.get('attest_uri', None)
        self.private_endpoint_connections = None


class AttestationProviderListResult(msrest.serialization.Model):
    """Attestation Providers List.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar system_data: The system metadata relating to this resource.
    :vartype system_data: ~azure.mgmt.attestation.models.SystemData
    :param value: Attestation Provider array.
    :type value: list[~azure.mgmt.attestation.models.AttestationProvider]
    """

    _validation = {
        'system_data': {'readonly': True},
    }

    _attribute_map = {
        'system_data': {'key': 'systemData', 'type': 'SystemData'},
        'value': {'key': 'value', 'type': '[AttestationProvider]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AttestationProviderListResult, self).__init__(**kwargs)
        self.system_data = None
        self.value = kwargs.get('value', None)


class AttestationServiceCreationParams(msrest.serialization.Model):
    """Parameters for creating an attestation provider.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. The supported Azure location where the attestation provider should
     be created.
    :type location: str
    :param tags: A set of tags. The tags that will be assigned to the attestation provider.
    :type tags: dict[str, str]
    :param properties: Required. Properties of the attestation provider.
    :type properties: ~azure.mgmt.attestation.models.AttestationServiceCreationSpecificParams
    """

    _validation = {
        'location': {'required': True},
        'properties': {'required': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'properties': {'key': 'properties', 'type': 'AttestationServiceCreationSpecificParams'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AttestationServiceCreationParams, self).__init__(**kwargs)
        self.location = kwargs['location']
        self.tags = kwargs.get('tags', None)
        self.properties = kwargs['properties']


class AttestationServiceCreationSpecificParams(msrest.serialization.Model):
    """Client supplied parameters used to create a new attestation provider.

    :param policy_signing_certificates: JSON Web Key Set defining a set of X.509 Certificates that
     will represent the parent certificate for the signing certificate used for policy operations.
    :type policy_signing_certificates: ~azure.mgmt.attestation.models.JSONWebKeySet
    """

    _attribute_map = {
        'policy_signing_certificates': {'key': 'policySigningCertificates', 'type': 'JSONWebKeySet'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AttestationServiceCreationSpecificParams, self).__init__(**kwargs)
        self.policy_signing_certificates = kwargs.get('policy_signing_certificates', None)


class AttestationServicePatchParams(msrest.serialization.Model):
    """Parameters for patching an attestation provider.

    :param tags: A set of tags. The tags that will be assigned to the attestation provider.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AttestationServicePatchParams, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)


class CloudErrorBody(msrest.serialization.Model):
    """An error response from Attestation.

    :param code: An identifier for the error. Codes are invariant and are intended to be consumed
     programmatically.
    :type code: str
    :param message: A message describing the error, intended to be suitable for displaying in a
     user interface.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CloudErrorBody, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)


class JSONWebKey(msrest.serialization.Model):
    """JSONWebKey.

    All required parameters must be populated in order to send to Azure.

    :param alg: Required. The "alg" (algorithm) parameter identifies the algorithm intended for
     use with the key.  The values used should either be registered in the
     IANA "JSON Web Signature and Encryption Algorithms" registry
     established by [JWA] or be a value that contains a Collision-
     Resistant Name.
    :type alg: str
    :param crv: The "crv" (curve) parameter identifies the curve type.
    :type crv: str
    :param d: RSA private exponent or ECC private key.
    :type d: str
    :param dp: RSA Private Key Parameter.
    :type dp: str
    :param dq: RSA Private Key Parameter.
    :type dq: str
    :param e: RSA public exponent, in Base64.
    :type e: str
    :param k: Symmetric key.
    :type k: str
    :param kid: Required. The "kid" (key ID) parameter is used to match a specific key.  This
     is used, for instance, to choose among a set of keys within a JWK Set
     during key rollover.  The structure of the "kid" value is
     unspecified.  When "kid" values are used within a JWK Set, different
     keys within the JWK Set SHOULD use distinct "kid" values.  (One
     example in which different keys might use the same "kid" value is if
     they have different "kty" (key type) values but are considered to be
     equivalent alternatives by the application using them.)  The "kid"
     value is a case-sensitive string.
    :type kid: str
    :param kty: Required. The "kty" (key type) parameter identifies the cryptographic algorithm
     family used with the key, such as "RSA" or "EC". "kty" values should
     either be registered in the IANA "JSON Web Key Types" registry
     established by [JWA] or be a value that contains a Collision-
     Resistant Name.  The "kty" value is a case-sensitive string.
    :type kty: str
    :param n: RSA modulus, in Base64.
    :type n: str
    :param p: RSA secret prime.
    :type p: str
    :param q: RSA secret prime, with p < q.
    :type q: str
    :param qi: RSA Private Key Parameter.
    :type qi: str
    :param use: Required. Use ("public key use") identifies the intended use of
     the public key. The "use" parameter is employed to indicate whether
     a public key is used for encrypting data or verifying the signature
     on data. Values are commonly "sig" (signature) or "enc" (encryption).
    :type use: str
    :param x: X coordinate for the Elliptic Curve point.
    :type x: str
    :param x5_c: The "x5c" (X.509 certificate chain) parameter contains a chain of one
     or more PKIX certificates [RFC5280].  The certificate chain is
     represented as a JSON array of certificate value strings.  Each
     string in the array is a base64-encoded (Section 4 of [RFC4648] --
     not base64url-encoded) DER [ITU.X690.1994] PKIX certificate value.
     The PKIX certificate containing the key value MUST be the first
     certificate.
    :type x5_c: list[str]
    :param y: Y coordinate for the Elliptic Curve point.
    :type y: str
    """

    _validation = {
        'alg': {'required': True},
        'kid': {'required': True},
        'kty': {'required': True},
        'use': {'required': True},
    }

    _attribute_map = {
        'alg': {'key': 'alg', 'type': 'str'},
        'crv': {'key': 'crv', 'type': 'str'},
        'd': {'key': 'd', 'type': 'str'},
        'dp': {'key': 'dp', 'type': 'str'},
        'dq': {'key': 'dq', 'type': 'str'},
        'e': {'key': 'e', 'type': 'str'},
        'k': {'key': 'k', 'type': 'str'},
        'kid': {'key': 'kid', 'type': 'str'},
        'kty': {'key': 'kty', 'type': 'str'},
        'n': {'key': 'n', 'type': 'str'},
        'p': {'key': 'p', 'type': 'str'},
        'q': {'key': 'q', 'type': 'str'},
        'qi': {'key': 'qi', 'type': 'str'},
        'use': {'key': 'use', 'type': 'str'},
        'x': {'key': 'x', 'type': 'str'},
        'x5_c': {'key': 'x5c', 'type': '[str]'},
        'y': {'key': 'y', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(JSONWebKey, self).__init__(**kwargs)
        self.alg = kwargs['alg']
        self.crv = kwargs.get('crv', None)
        self.d = kwargs.get('d', None)
        self.dp = kwargs.get('dp', None)
        self.dq = kwargs.get('dq', None)
        self.e = kwargs.get('e', None)
        self.k = kwargs.get('k', None)
        self.kid = kwargs['kid']
        self.kty = kwargs['kty']
        self.n = kwargs.get('n', None)
        self.p = kwargs.get('p', None)
        self.q = kwargs.get('q', None)
        self.qi = kwargs.get('qi', None)
        self.use = kwargs['use']
        self.x = kwargs.get('x', None)
        self.x5_c = kwargs.get('x5_c', None)
        self.y = kwargs.get('y', None)


class JSONWebKeySet(msrest.serialization.Model):
    """JSONWebKeySet.

    :param keys: The value of the "keys" parameter is an array of JWK values.  By
     default, the order of the JWK values within the array does not imply
     an order of preference among them, although applications of JWK Sets
     can choose to assign a meaning to the order for their purposes, if
     desired.
    :type keys: list[~azure.mgmt.attestation.models.JSONWebKey]
    """

    _attribute_map = {
        'keys': {'key': 'keys', 'type': '[JSONWebKey]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(JSONWebKeySet, self).__init__(**kwargs)
        self.keys = kwargs.get('keys', None)


class OperationList(msrest.serialization.Model):
    """List of supported operations.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar system_data: The system metadata relating to this resource.
    :vartype system_data: ~azure.mgmt.attestation.models.SystemData
    :param value: List of supported operations.
    :type value: list[~azure.mgmt.attestation.models.OperationsDefinition]
    """

    _validation = {
        'system_data': {'readonly': True},
    }

    _attribute_map = {
        'system_data': {'key': 'systemData', 'type': 'SystemData'},
        'value': {'key': 'value', 'type': '[OperationsDefinition]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationList, self).__init__(**kwargs)
        self.system_data = None
        self.value = kwargs.get('value', None)


class OperationsDefinition(msrest.serialization.Model):
    """Definition object with the name and properties of an operation.

    :param name: Name of the operation.
    :type name: str
    :param display: Display object with properties of the operation.
    :type display: ~azure.mgmt.attestation.models.OperationsDisplayDefinition
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationsDisplayDefinition'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationsDefinition, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display = kwargs.get('display', None)


class OperationsDisplayDefinition(msrest.serialization.Model):
    """Display object with properties of the operation.

    :param provider: Resource provider of the operation.
    :type provider: str
    :param resource: Resource for the operation.
    :type resource: str
    :param operation: Short description of the operation.
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
        **kwargs
    ):
        super(OperationsDisplayDefinition, self).__init__(**kwargs)
        self.provider = kwargs.get('provider', None)
        self.resource = kwargs.get('resource', None)
        self.operation = kwargs.get('operation', None)
        self.description = kwargs.get('description', None)


class PrivateEndpoint(msrest.serialization.Model):
    """Private endpoint object properties.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Full identifier of the private endpoint resource.
    :vartype id: str
    """

    _validation = {
        'id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateEndpoint, self).__init__(**kwargs)
        self.id = None


class PrivateEndpointConnection(Resource):
    """Private endpoint connection resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
    :vartype type: str
    :param private_endpoint: Properties of the private endpoint object.
    :type private_endpoint: ~azure.mgmt.attestation.models.PrivateEndpoint
    :param private_link_service_connection_state: Approval state of the private link connection.
    :type private_link_service_connection_state:
     ~azure.mgmt.attestation.models.PrivateLinkServiceConnectionState
    :ivar provisioning_state: Provisioning state of the private endpoint connection. Possible
     values include: "Succeeded", "Creating", "Deleting", "Failed".
    :vartype provisioning_state: str or
     ~azure.mgmt.attestation.models.PrivateEndpointConnectionProvisioningState
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'private_endpoint': {'key': 'properties.privateEndpoint', 'type': 'PrivateEndpoint'},
        'private_link_service_connection_state': {'key': 'properties.privateLinkServiceConnectionState', 'type': 'PrivateLinkServiceConnectionState'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateEndpointConnection, self).__init__(**kwargs)
        self.private_endpoint = kwargs.get('private_endpoint', None)
        self.private_link_service_connection_state = kwargs.get('private_link_service_connection_state', None)
        self.provisioning_state = None


class PrivateEndpointConnectionItem(msrest.serialization.Model):
    """Private endpoint connection item.

    :param name: Name of the connection item.
    :type name: str
    :param id: ID of  the connection item.
    :type id: str
    :param type: Type of the connection item.
    :type type: str
    :param properties:
    :type properties: ~azure.mgmt.attestation.models.PrivateLinkConnectionItemProperties
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'PrivateLinkConnectionItemProperties'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateEndpointConnectionItem, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.id = kwargs.get('id', None)
        self.type = kwargs.get('type', None)
        self.properties = kwargs.get('properties', None)


class PrivateEndpointConnectionsListResult(msrest.serialization.Model):
    """A list of private endpoint connections.

    :param value: Array of private endpoint connections.
    :type value: list[~azure.mgmt.attestation.models.PrivateEndpointConnection]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[PrivateEndpointConnection]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateEndpointConnectionsListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)


class PrivateLinkConnectionItemProperties(msrest.serialization.Model):
    """PrivateLinkConnectionItemProperties.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar provisioning_state: Indicates whether the connection has been Approved/Rejected/Removed
     by the owner of the service. Possible values include: "Succeeded", "Creating", "Deleting",
     "Failed".
    :vartype provisioning_state: str or
     ~azure.mgmt.attestation.models.PrivateEndpointConnectionProvisioningState
    :param private_endpoint:
    :type private_endpoint:
     ~azure.mgmt.attestation.models.PrivateLinkConnectionItemPropertiesPrivateEndpoint
    :param private_link_service_connection_state: A collection of information about the state of
     the connection between service consumer and provider.
    :type private_link_service_connection_state:
     ~azure.mgmt.attestation.models.PrivateLinkServiceConnectionState
    """

    _validation = {
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'private_endpoint': {'key': 'privateEndpoint', 'type': 'PrivateLinkConnectionItemPropertiesPrivateEndpoint'},
        'private_link_service_connection_state': {'key': 'privateLinkServiceConnectionState', 'type': 'PrivateLinkServiceConnectionState'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateLinkConnectionItemProperties, self).__init__(**kwargs)
        self.provisioning_state = None
        self.private_endpoint = kwargs.get('private_endpoint', None)
        self.private_link_service_connection_state = kwargs.get('private_link_service_connection_state', None)


class PrivateLinkConnectionItemPropertiesPrivateEndpoint(msrest.serialization.Model):
    """PrivateLinkConnectionItemPropertiesPrivateEndpoint.

    :param id: Identifier for the endpoint.
    :type id: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateLinkConnectionItemPropertiesPrivateEndpoint, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)


class PrivateLinkResource(Resource):
    """A private link resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
    :vartype type: str
    :ivar group_id: Group identifier of private link resource.
    :vartype group_id: str
    :ivar required_members: Required member names of private link resource.
    :vartype required_members: list[str]
    :param required_zone_names: Required DNS zone names of the the private link resource.
    :type required_zone_names: list[str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'group_id': {'readonly': True},
        'required_members': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'group_id': {'key': 'properties.groupId', 'type': 'str'},
        'required_members': {'key': 'properties.requiredMembers', 'type': '[str]'},
        'required_zone_names': {'key': 'properties.requiredZoneNames', 'type': '[str]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateLinkResource, self).__init__(**kwargs)
        self.group_id = None
        self.required_members = None
        self.required_zone_names = kwargs.get('required_zone_names', None)


class PrivateLinkResourceListResult(msrest.serialization.Model):
    """A list of private link resources.

    :param value: Array of private link resources.
    :type value: list[~azure.mgmt.attestation.models.PrivateLinkResource]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[PrivateLinkResource]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateLinkResourceListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)


class PrivateLinkServiceConnectionState(msrest.serialization.Model):
    """A collection of information about the state of the connection between service consumer and provider.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar status: Indicates whether the connection has been Approved/Rejected/Removed by the owner
     of the service. Possible values include: "Succeeded", "Creating", "Deleting", "Failed".
    :vartype status: str or
     ~azure.mgmt.attestation.models.PrivateEndpointConnectionProvisioningState
    :param description: The reason for approval/rejection of the connection.
    :type description: str
    :param actions_required: A message indicating if changes on the service provider require any
     updates on the consumer.
    :type actions_required: str
    """

    _validation = {
        'status': {'readonly': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'actions_required': {'key': 'actionsRequired', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateLinkServiceConnectionState, self).__init__(**kwargs)
        self.status = None
        self.description = kwargs.get('description', None)
        self.actions_required = kwargs.get('actions_required', None)


class SystemData(msrest.serialization.Model):
    """Metadata pertaining to creation and last modification of the resource.

    :param created_by: The identity that created the resource.
    :type created_by: str
    :param created_by_type: The type of identity that created the resource. Possible values
     include: "User", "Application", "ManagedIdentity", "Key".
    :type created_by_type: str or ~azure.mgmt.attestation.models.CreatedByType
    :param created_at: The timestamp of resource creation (UTC).
    :type created_at: ~datetime.datetime
    :param last_modified_by: The identity that last modified the resource.
    :type last_modified_by: str
    :param last_modified_by_type: The type of identity that last modified the resource. Possible
     values include: "User", "Application", "ManagedIdentity", "Key".
    :type last_modified_by_type: str or ~azure.mgmt.attestation.models.CreatedByType
    :param last_modified_at: The type of identity that last modified the resource.
    :type last_modified_at: ~datetime.datetime
    """

    _attribute_map = {
        'created_by': {'key': 'createdBy', 'type': 'str'},
        'created_by_type': {'key': 'createdByType', 'type': 'str'},
        'created_at': {'key': 'createdAt', 'type': 'iso-8601'},
        'last_modified_by': {'key': 'lastModifiedBy', 'type': 'str'},
        'last_modified_by_type': {'key': 'lastModifiedByType', 'type': 'str'},
        'last_modified_at': {'key': 'lastModifiedAt', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SystemData, self).__init__(**kwargs)
        self.created_by = kwargs.get('created_by', None)
        self.created_by_type = kwargs.get('created_by_type', None)
        self.created_at = kwargs.get('created_at', None)
        self.last_modified_by = kwargs.get('last_modified_by', None)
        self.last_modified_by_type = kwargs.get('last_modified_by_type', None)
        self.last_modified_at = kwargs.get('last_modified_at', None)
