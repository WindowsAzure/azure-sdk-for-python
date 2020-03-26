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


class AsyncOperationResult(Model):
    """Result of a long running operation.

    :param status: current status of a long running operation.
    :type status: str
    :param error: Error message containing code, description and details
    :type error: ~azure.mgmt.iothubprovisioningservices.models.ErrorMesssage
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'error': {'key': 'error', 'type': 'ErrorMesssage'},
    }

    def __init__(self, *, status: str=None, error=None, **kwargs) -> None:
        super(AsyncOperationResult, self).__init__(**kwargs)
        self.status = status
        self.error = error


class CertificateBodyDescription(Model):
    """The JSON-serialized X509 Certificate.

    :param certificate: Base-64 representation of the X509 leaf certificate
     .cer file or just .pem file content.
    :type certificate: str
    """

    _attribute_map = {
        'certificate': {'key': 'certificate', 'type': 'str'},
    }

    def __init__(self, *, certificate: str=None, **kwargs) -> None:
        super(CertificateBodyDescription, self).__init__(**kwargs)
        self.certificate = certificate


class CertificateListDescription(Model):
    """The JSON-serialized array of Certificate objects.

    :param value: The array of Certificate objects.
    :type value:
     list[~azure.mgmt.iothubprovisioningservices.models.CertificateResponse]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[CertificateResponse]'},
    }

    def __init__(self, *, value=None, **kwargs) -> None:
        super(CertificateListDescription, self).__init__(**kwargs)
        self.value = value


class CertificateProperties(Model):
    """The description of an X509 CA Certificate.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar subject: The certificate's subject name.
    :vartype subject: str
    :ivar expiry: The certificate's expiration date and time.
    :vartype expiry: datetime
    :ivar thumbprint: The certificate's thumbprint.
    :vartype thumbprint: str
    :ivar is_verified: Determines whether certificate has been verified.
    :vartype is_verified: bool
    :ivar created: The certificate's creation date and time.
    :vartype created: datetime
    :ivar updated: The certificate's last update date and time.
    :vartype updated: datetime
    """

    _validation = {
        'subject': {'readonly': True},
        'expiry': {'readonly': True},
        'thumbprint': {'readonly': True},
        'is_verified': {'readonly': True},
        'created': {'readonly': True},
        'updated': {'readonly': True},
    }

    _attribute_map = {
        'subject': {'key': 'subject', 'type': 'str'},
        'expiry': {'key': 'expiry', 'type': 'rfc-1123'},
        'thumbprint': {'key': 'thumbprint', 'type': 'str'},
        'is_verified': {'key': 'isVerified', 'type': 'bool'},
        'created': {'key': 'created', 'type': 'rfc-1123'},
        'updated': {'key': 'updated', 'type': 'rfc-1123'},
    }

    def __init__(self, **kwargs) -> None:
        super(CertificateProperties, self).__init__(**kwargs)
        self.subject = None
        self.expiry = None
        self.thumbprint = None
        self.is_verified = None
        self.created = None
        self.updated = None


class CertificateResponse(Model):
    """The X509 Certificate.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param properties: properties of a certificate
    :type properties:
     ~azure.mgmt.iothubprovisioningservices.models.CertificateProperties
    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: The name of the certificate.
    :vartype name: str
    :ivar etag: The entity tag.
    :vartype etag: str
    :ivar type: The resource type.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'etag': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'CertificateProperties'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, properties=None, **kwargs) -> None:
        super(CertificateResponse, self).__init__(**kwargs)
        self.properties = properties
        self.id = None
        self.name = None
        self.etag = None
        self.type = None


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class ErrorDetails(Model):
    """Error details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: The error code.
    :vartype code: str
    :ivar http_status_code: The HTTP status code.
    :vartype http_status_code: str
    :ivar message: The error message.
    :vartype message: str
    :ivar details: The error details.
    :vartype details: str
    """

    _validation = {
        'code': {'readonly': True},
        'http_status_code': {'readonly': True},
        'message': {'readonly': True},
        'details': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'http_status_code': {'key': 'httpStatusCode', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(ErrorDetails, self).__init__(**kwargs)
        self.code = None
        self.http_status_code = None
        self.message = None
        self.details = None


class ErrorDetailsException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorDetails'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorDetailsException, self).__init__(deserialize, response, 'ErrorDetails', *args)


class ErrorMesssage(Model):
    """Error response containing message and code.

    :param code: standard error code
    :type code: str
    :param message: standard error description
    :type message: str
    :param details: detailed summary of error
    :type details: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': 'str'},
    }

    def __init__(self, *, code: str=None, message: str=None, details: str=None, **kwargs) -> None:
        super(ErrorMesssage, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.details = details


class IotDpsPropertiesDescription(Model):
    """the service specific properties of a provisioning service, including keys,
    linked iot hubs, current state, and system generated properties such as
    hostname and idScope.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param state: Current state of the provisioning service. Possible values
     include: 'Activating', 'Active', 'Deleting', 'Deleted',
     'ActivationFailed', 'DeletionFailed', 'Transitioning', 'Suspending',
     'Suspended', 'Resuming', 'FailingOver', 'FailoverFailed'
    :type state: str or ~azure.mgmt.iothubprovisioningservices.models.State
    :param provisioning_state: The ARM provisioning state of the provisioning
     service.
    :type provisioning_state: str
    :param iot_hubs: List of IoT hubs associated with this provisioning
     service.
    :type iot_hubs:
     list[~azure.mgmt.iothubprovisioningservices.models.IotHubDefinitionDescription]
    :param allocation_policy: Allocation policy to be used by this
     provisioning service. Possible values include: 'Hashed', 'GeoLatency',
     'Static'
    :type allocation_policy: str or
     ~azure.mgmt.iothubprovisioningservices.models.AllocationPolicy
    :ivar service_operations_host_name: Service endpoint for provisioning
     service.
    :vartype service_operations_host_name: str
    :ivar device_provisioning_host_name: Device endpoint for this provisioning
     service.
    :vartype device_provisioning_host_name: str
    :ivar id_scope: Unique identifier of this provisioning service.
    :vartype id_scope: str
    :param authorization_policies: List of authorization keys for a
     provisioning service.
    :type authorization_policies:
     list[~azure.mgmt.iothubprovisioningservices.models.SharedAccessSignatureAuthorizationRuleAccessRightsDescription]
    """

    _validation = {
        'service_operations_host_name': {'readonly': True},
        'device_provisioning_host_name': {'readonly': True},
        'id_scope': {'readonly': True},
    }

    _attribute_map = {
        'state': {'key': 'state', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'iot_hubs': {'key': 'iotHubs', 'type': '[IotHubDefinitionDescription]'},
        'allocation_policy': {'key': 'allocationPolicy', 'type': 'str'},
        'service_operations_host_name': {'key': 'serviceOperationsHostName', 'type': 'str'},
        'device_provisioning_host_name': {'key': 'deviceProvisioningHostName', 'type': 'str'},
        'id_scope': {'key': 'idScope', 'type': 'str'},
        'authorization_policies': {'key': 'authorizationPolicies', 'type': '[SharedAccessSignatureAuthorizationRuleAccessRightsDescription]'},
    }

    def __init__(self, *, state=None, provisioning_state: str=None, iot_hubs=None, allocation_policy=None, authorization_policies=None, **kwargs) -> None:
        super(IotDpsPropertiesDescription, self).__init__(**kwargs)
        self.state = state
        self.provisioning_state = provisioning_state
        self.iot_hubs = iot_hubs
        self.allocation_policy = allocation_policy
        self.service_operations_host_name = None
        self.device_provisioning_host_name = None
        self.id_scope = None
        self.authorization_policies = authorization_policies


class IotDpsSkuDefinition(Model):
    """Available SKUs of tier and units.

    :param name: Sku name. Possible values include: 'S1'
    :type name: str or ~azure.mgmt.iothubprovisioningservices.models.IotDpsSku
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, name=None, **kwargs) -> None:
        super(IotDpsSkuDefinition, self).__init__(**kwargs)
        self.name = name


class IotDpsSkuInfo(Model):
    """List of possible provisioning service SKUs.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param name: Sku name. Possible values include: 'S1'
    :type name: str or ~azure.mgmt.iothubprovisioningservices.models.IotDpsSku
    :ivar tier: Pricing tier name of the provisioning service.
    :vartype tier: str
    :param capacity: The number of units to provision
    :type capacity: long
    """

    _validation = {
        'tier': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'long'},
    }

    def __init__(self, *, name=None, capacity: int=None, **kwargs) -> None:
        super(IotDpsSkuInfo, self).__init__(**kwargs)
        self.name = name
        self.tier = None
        self.capacity = capacity


class IotHubDefinitionDescription(Model):
    """Description of the IoT hub.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param apply_allocation_policy: flag for applying allocationPolicy or not
     for a given iot hub.
    :type apply_allocation_policy: bool
    :param allocation_weight: weight to apply for a given iot h.
    :type allocation_weight: int
    :ivar name: Host name of the IoT hub.
    :vartype name: str
    :param connection_string: Required. Connection string og the IoT hub.
    :type connection_string: str
    :param location: Required. ARM region of the IoT hub.
    :type location: str
    """

    _validation = {
        'name': {'readonly': True},
        'connection_string': {'required': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'apply_allocation_policy': {'key': 'applyAllocationPolicy', 'type': 'bool'},
        'allocation_weight': {'key': 'allocationWeight', 'type': 'int'},
        'name': {'key': 'name', 'type': 'str'},
        'connection_string': {'key': 'connectionString', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(self, *, connection_string: str, location: str, apply_allocation_policy: bool=None, allocation_weight: int=None, **kwargs) -> None:
        super(IotHubDefinitionDescription, self).__init__(**kwargs)
        self.apply_allocation_policy = apply_allocation_policy
        self.allocation_weight = allocation_weight
        self.name = None
        self.connection_string = connection_string
        self.location = location


class NameAvailabilityInfo(Model):
    """Description of name availability.

    :param name_available: specifies if a name is available or not
    :type name_available: bool
    :param reason: specifies the reason a name is unavailable. Possible values
     include: 'Invalid', 'AlreadyExists'
    :type reason: str or
     ~azure.mgmt.iothubprovisioningservices.models.NameUnavailabilityReason
    :param message: message containing a detailed reason name is unavailable
    :type message: str
    """

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, *, name_available: bool=None, reason=None, message: str=None, **kwargs) -> None:
        super(NameAvailabilityInfo, self).__init__(**kwargs)
        self.name_available = name_available
        self.reason = reason
        self.message = message


class Operation(Model):
    """IoT Hub REST API operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Operation name: {provider}/{resource}/{read | write | action |
     delete}
    :vartype name: str
    :param display: The object that represents the operation.
    :type display:
     ~azure.mgmt.iothubprovisioningservices.models.OperationDisplay
    """

    _validation = {
        'name': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(self, *, display=None, **kwargs) -> None:
        super(Operation, self).__init__(**kwargs)
        self.name = None
        self.display = display


class OperationDisplay(Model):
    """The object that represents the operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provider: Service provider: Microsoft Devices.
    :vartype provider: str
    :ivar resource: Resource Type: ProvisioningServices.
    :vartype resource: str
    :ivar operation: Name of the operation.
    :vartype operation: str
    """

    _validation = {
        'provider': {'readonly': True},
        'resource': {'readonly': True},
        'operation': {'readonly': True},
    }

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = None
        self.resource = None
        self.operation = None


class OperationInputs(Model):
    """Input values for operation results call.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the Provisioning Service to check.
    :type name: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, name: str, **kwargs) -> None:
        super(OperationInputs, self).__init__(**kwargs)
        self.name = name


class Resource(Model):
    """The common properties of an Azure resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param location: Required. The resource location.
    :type location: str
    :param tags: The resource tags.
    :type tags: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True, 'pattern': r'^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{2,49}[a-zA-Z0-9]$'},
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


class ProvisioningServiceDescription(Resource):
    """The description of the provisioning service.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param location: Required. The resource location.
    :type location: str
    :param tags: The resource tags.
    :type tags: dict[str, str]
    :param etag: The Etag field is *not* required. If it is provided in the
     response body, it must also be provided as a header per the normal ETag
     convention.
    :type etag: str
    :param properties: Required. Service specific properties for a
     provisioning service
    :type properties:
     ~azure.mgmt.iothubprovisioningservices.models.IotDpsPropertiesDescription
    :param sku: Required. Sku info for a provisioning Service.
    :type sku: ~azure.mgmt.iothubprovisioningservices.models.IotDpsSkuInfo
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True, 'pattern': r'^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{2,49}[a-zA-Z0-9]$'},
        'type': {'readonly': True},
        'location': {'required': True},
        'properties': {'required': True},
        'sku': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'etag': {'key': 'etag', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'IotDpsPropertiesDescription'},
        'sku': {'key': 'sku', 'type': 'IotDpsSkuInfo'},
    }

    def __init__(self, *, location: str, properties, sku, tags=None, etag: str=None, **kwargs) -> None:
        super(ProvisioningServiceDescription, self).__init__(location=location, tags=tags, **kwargs)
        self.etag = etag
        self.properties = properties
        self.sku = sku


class SharedAccessSignatureAuthorizationRuleAccessRightsDescription(Model):
    """Description of the shared access key.

    All required parameters must be populated in order to send to Azure.

    :param key_name: Required. Name of the key.
    :type key_name: str
    :param primary_key: Primary SAS key value.
    :type primary_key: str
    :param secondary_key: Secondary SAS key value.
    :type secondary_key: str
    :param rights: Required. Rights that this key has. Possible values
     include: 'ServiceConfig', 'EnrollmentRead', 'EnrollmentWrite',
     'DeviceConnect', 'RegistrationStatusRead', 'RegistrationStatusWrite'
    :type rights: str or
     ~azure.mgmt.iothubprovisioningservices.models.AccessRightsDescription
    """

    _validation = {
        'key_name': {'required': True},
        'rights': {'required': True},
    }

    _attribute_map = {
        'key_name': {'key': 'keyName', 'type': 'str'},
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
        'rights': {'key': 'rights', 'type': 'str'},
    }

    def __init__(self, *, key_name: str, rights, primary_key: str=None, secondary_key: str=None, **kwargs) -> None:
        super(SharedAccessSignatureAuthorizationRuleAccessRightsDescription, self).__init__(**kwargs)
        self.key_name = key_name
        self.primary_key = primary_key
        self.secondary_key = secondary_key
        self.rights = rights


class TagsResource(Model):
    """A container holding only the Tags for a resource, allowing the user to
    update the tags on a Provisioning Service instance.

    :param tags: Resource tags
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, tags=None, **kwargs) -> None:
        super(TagsResource, self).__init__(**kwargs)
        self.tags = tags


class VerificationCodeRequest(Model):
    """The JSON-serialized leaf certificate.

    :param certificate: base-64 representation of X509 certificate .cer file
     or just .pem file content.
    :type certificate: str
    """

    _attribute_map = {
        'certificate': {'key': 'certificate', 'type': 'str'},
    }

    def __init__(self, *, certificate: str=None, **kwargs) -> None:
        super(VerificationCodeRequest, self).__init__(**kwargs)
        self.certificate = certificate


class VerificationCodeResponse(Model):
    """Description of the response of the verification code.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Name of certificate.
    :vartype name: str
    :ivar etag: Request etag.
    :vartype etag: str
    :ivar id: The resource identifier.
    :vartype id: str
    :ivar type: The resource type.
    :vartype type: str
    :param properties:
    :type properties:
     ~azure.mgmt.iothubprovisioningservices.models.VerificationCodeResponseProperties
    """

    _validation = {
        'name': {'readonly': True},
        'etag': {'readonly': True},
        'id': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'VerificationCodeResponseProperties'},
    }

    def __init__(self, *, properties=None, **kwargs) -> None:
        super(VerificationCodeResponse, self).__init__(**kwargs)
        self.name = None
        self.etag = None
        self.id = None
        self.type = None
        self.properties = properties


class VerificationCodeResponseProperties(Model):
    """VerificationCodeResponseProperties.

    :param verification_code: Verification code.
    :type verification_code: str
    :param subject: Certificate subject.
    :type subject: str
    :param expiry: Code expiry.
    :type expiry: str
    :param thumbprint: Certificate thumbprint.
    :type thumbprint: str
    :param is_verified: Indicate if the certificate is verified by owner of
     private key.
    :type is_verified: bool
    :param created: Certificate created time.
    :type created: str
    :param updated: Certificate updated time.
    :type updated: str
    """

    _attribute_map = {
        'verification_code': {'key': 'verificationCode', 'type': 'str'},
        'subject': {'key': 'subject', 'type': 'str'},
        'expiry': {'key': 'expiry', 'type': 'str'},
        'thumbprint': {'key': 'thumbprint', 'type': 'str'},
        'is_verified': {'key': 'isVerified', 'type': 'bool'},
        'created': {'key': 'created', 'type': 'str'},
        'updated': {'key': 'updated', 'type': 'str'},
    }

    def __init__(self, *, verification_code: str=None, subject: str=None, expiry: str=None, thumbprint: str=None, is_verified: bool=None, created: str=None, updated: str=None, **kwargs) -> None:
        super(VerificationCodeResponseProperties, self).__init__(**kwargs)
        self.verification_code = verification_code
        self.subject = subject
        self.expiry = expiry
        self.thumbprint = thumbprint
        self.is_verified = is_verified
        self.created = created
        self.updated = updated
