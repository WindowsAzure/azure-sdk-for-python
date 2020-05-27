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


class Authorization(Model):
    """Authorization tuple containing principal Id (of user/service
    principal/security group) and role definition id.

    All required parameters must be populated in order to send to Azure.

    :param principal_id: Required. Principal Id of the security group/service
     principal/user that would be assigned permissions to the projected
     subscription
    :type principal_id: str
    :param principal_id_display_name: Display name of the principal Id.
    :type principal_id_display_name: str
    :param role_definition_id: Required. The role definition identifier. This
     role will define all the permissions that the security group/service
     principal/user must have on the projected subscription. This role cannot
     be an owner role.
    :type role_definition_id: str
    :param delegated_role_definition_ids: The delegatedRoleDefinitionIds field
     is required when the roleDefinitionId refers to the User Access
     Administrator Role. It is the list of role definition ids which define all
     the permissions that the user in the authorization can assign to other
     security groups/service principals/users.
    :type delegated_role_definition_ids: list[str]
    """

    _validation = {
        'principal_id': {'required': True},
        'role_definition_id': {'required': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'principal_id_display_name': {'key': 'principalIdDisplayName', 'type': 'str'},
        'role_definition_id': {'key': 'roleDefinitionId', 'type': 'str'},
        'delegated_role_definition_ids': {'key': 'delegatedRoleDefinitionIds', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(Authorization, self).__init__(**kwargs)
        self.principal_id = kwargs.get('principal_id', None)
        self.principal_id_display_name = kwargs.get('principal_id_display_name', None)
        self.role_definition_id = kwargs.get('role_definition_id', None)
        self.delegated_role_definition_ids = kwargs.get('delegated_role_definition_ids', None)


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class EligibleAuthorization(Model):
    """Eligible authorization tuple containing principle Id (of user/service
    principal/security group), role definition id, and the just-in-time access
    setting.

    All required parameters must be populated in order to send to Azure.

    :param principal_id: Required. Principal Id of the security group/service
     principal/user that would be delegated permissions to the projected
     subscription
    :type principal_id: str
    :param principal_id_display_name: Display name of the principal Id.
    :type principal_id_display_name: str
    :param role_definition_id: Required. The role definition identifier. This
     role will delegate all the permissions that the security group/service
     principal/user must have on the projected subscription. This role cannot
     be an owner role.
    :type role_definition_id: str
    :param just_in_time_access_policy: Just-in-time access policy setting.
    :type just_in_time_access_policy:
     ~azure.mgmt.managedservices.models.JustInTimeAccessPolicy
    """

    _validation = {
        'principal_id': {'required': True},
        'role_definition_id': {'required': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'principal_id_display_name': {'key': 'principalIdDisplayName', 'type': 'str'},
        'role_definition_id': {'key': 'roleDefinitionId', 'type': 'str'},
        'just_in_time_access_policy': {'key': 'justInTimeAccessPolicy', 'type': 'JustInTimeAccessPolicy'},
    }

    def __init__(self, **kwargs):
        super(EligibleAuthorization, self).__init__(**kwargs)
        self.principal_id = kwargs.get('principal_id', None)
        self.principal_id_display_name = kwargs.get('principal_id_display_name', None)
        self.role_definition_id = kwargs.get('role_definition_id', None)
        self.just_in_time_access_policy = kwargs.get('just_in_time_access_policy', None)


class ErrorResponse(Model):
    """Error response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar error: Error response indicates Azure Resource Manager is not able
     to process the incoming request. The reason is provided in the error
     message.
    :vartype error: ~azure.mgmt.managedservices.models.ErrorResponseError
    """

    _validation = {
        'error': {'readonly': True},
    }

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorResponseError'},
    }

    def __init__(self, **kwargs):
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = None


class ErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorResponseException, self).__init__(deserialize, response, 'ErrorResponse', *args)


class ErrorResponseError(Model):
    """Error response indicates Azure Resource Manager is not able to process the
    incoming request. The reason is provided in the error message.

    All required parameters must be populated in order to send to Azure.

    :param code: Required. Error code.
    :type code: str
    :param message: Required. Error message indicating why the operation
     failed.
    :type message: str
    """

    _validation = {
        'code': {'required': True},
        'message': {'required': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ErrorResponseError, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)


class JustInTimeAccessPolicy(Model):
    """Just-in-time access policy setting.

    All required parameters must be populated in order to send to Azure.

    :param multi_factor_auth_provider: Required. MFA provider. Possible values
     include: 'Azure', 'None'
    :type multi_factor_auth_provider: str or
     ~azure.mgmt.managedservices.models.MultiFactorAuthProvider
    :param maximum_activation_duration: Maximum access duration in ISO 8601
     format.  The default value is "PT8H".
    :type maximum_activation_duration: timedelta
    """

    _validation = {
        'multi_factor_auth_provider': {'required': True},
    }

    _attribute_map = {
        'multi_factor_auth_provider': {'key': 'multiFactorAuthProvider', 'type': 'str'},
        'maximum_activation_duration': {'key': 'maximumActivationDuration', 'type': 'duration'},
    }

    def __init__(self, **kwargs):
        super(JustInTimeAccessPolicy, self).__init__(**kwargs)
        self.multi_factor_auth_provider = kwargs.get('multi_factor_auth_provider', None)
        self.maximum_activation_duration = kwargs.get('maximum_activation_duration', None)


class Operation(Model):
    """Object that describes a single Microsoft.ManagedServices operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Operation name: {provider}/{resource}/{operation}
    :vartype name: str
    :ivar display: The object that represents the operation.
    :vartype display: ~azure.mgmt.managedservices.models.OperationDisplay
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
    """The object that represents the operation.

    :param provider: Service provider: Microsoft.ManagedServices
    :type provider: str
    :param resource: Resource on which the operation is performed:
     Registration definition, registration assignment etc.
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

    def __init__(self, **kwargs):
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = kwargs.get('provider', None)
        self.resource = kwargs.get('resource', None)
        self.operation = kwargs.get('operation', None)
        self.description = kwargs.get('description', None)


class OperationList(Model):
    """List of the operations.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar value: List of Microsoft.ManagedServices operations.
    :vartype value: list[~azure.mgmt.managedservices.models.Operation]
    """

    _validation = {
        'value': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Operation]'},
    }

    def __init__(self, **kwargs):
        super(OperationList, self).__init__(**kwargs)
        self.value = None


class Plan(Model):
    """Plan details for the managed services.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The plan name.
    :type name: str
    :param publisher: Required. The publisher ID.
    :type publisher: str
    :param product: Required. The product code.
    :type product: str
    :param version: Required. The plan's version.
    :type version: str
    """

    _validation = {
        'name': {'required': True},
        'publisher': {'required': True},
        'product': {'required': True},
        'version': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'publisher': {'key': 'publisher', 'type': 'str'},
        'product': {'key': 'product', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Plan, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.publisher = kwargs.get('publisher', None)
        self.product = kwargs.get('product', None)
        self.version = kwargs.get('version', None)


class RegistrationAssignment(Model):
    """Registration assignment.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param properties: Properties of a registration assignment.
    :type properties:
     ~azure.mgmt.managedservices.models.RegistrationAssignmentProperties
    :ivar id: The fully qualified path of the registration assignment.
    :vartype id: str
    :ivar type: Type of the resource.
    :vartype type: str
    :ivar name: Name of the registration assignment.
    :vartype name: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'RegistrationAssignmentProperties'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RegistrationAssignment, self).__init__(**kwargs)
        self.properties = kwargs.get('properties', None)
        self.id = None
        self.type = None
        self.name = None


class RegistrationAssignmentProperties(Model):
    """Properties of a registration assignment.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param registration_definition_id: Required. Fully qualified path of the
     registration definition.
    :type registration_definition_id: str
    :ivar provisioning_state: Current state of the registration assignment.
     Possible values include: 'NotSpecified', 'Accepted', 'Running', 'Ready',
     'Creating', 'Created', 'Deleting', 'Deleted', 'Canceled', 'Failed',
     'Succeeded', 'Updating'
    :vartype provisioning_state: str or
     ~azure.mgmt.managedservices.models.ProvisioningState
    :ivar registration_definition: Registration definition inside registration
     assignment.
    :vartype registration_definition:
     ~azure.mgmt.managedservices.models.RegistrationAssignmentPropertiesRegistrationDefinition
    """

    _validation = {
        'registration_definition_id': {'required': True},
        'provisioning_state': {'readonly': True},
        'registration_definition': {'readonly': True},
    }

    _attribute_map = {
        'registration_definition_id': {'key': 'registrationDefinitionId', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'registration_definition': {'key': 'registrationDefinition', 'type': 'RegistrationAssignmentPropertiesRegistrationDefinition'},
    }

    def __init__(self, **kwargs):
        super(RegistrationAssignmentProperties, self).__init__(**kwargs)
        self.registration_definition_id = kwargs.get('registration_definition_id', None)
        self.provisioning_state = None
        self.registration_definition = None


class RegistrationAssignmentPropertiesRegistrationDefinition(Model):
    """Registration definition inside registration assignment.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param properties: Properties of registration definition inside
     registration assignment.
    :type properties:
     ~azure.mgmt.managedservices.models.RegistrationAssignmentPropertiesRegistrationDefinitionProperties
    :param plan: Plan details for the managed services.
    :type plan: ~azure.mgmt.managedservices.models.Plan
    :ivar id: Fully qualified path of the registration definition.
    :vartype id: str
    :ivar type: Type of the resource
     (Microsoft.ManagedServices/registrationDefinitions).
    :vartype type: str
    :ivar name: Name of the registration definition.
    :vartype name: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'RegistrationAssignmentPropertiesRegistrationDefinitionProperties'},
        'plan': {'key': 'plan', 'type': 'Plan'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RegistrationAssignmentPropertiesRegistrationDefinition, self).__init__(**kwargs)
        self.properties = kwargs.get('properties', None)
        self.plan = kwargs.get('plan', None)
        self.id = None
        self.type = None
        self.name = None


class RegistrationAssignmentPropertiesRegistrationDefinitionProperties(Model):
    """Properties of registration definition inside registration assignment.

    :param description: Description of the registration definition.
    :type description: str
    :param authorizations: Authorization tuple containing principal id of the
     user/security group or service principal and id of the build-in role.
    :type authorizations:
     list[~azure.mgmt.managedservices.models.Authorization]
    :param eligible_authorizations: Eligible PIM authorization tuple
     containing principal id of the user/security group or service principal,
     id of the built-in role, and just-in-time access policy setting
    :type eligible_authorizations:
     list[~azure.mgmt.managedservices.models.EligibleAuthorization]
    :param registration_definition_name: Name of the registration definition.
    :type registration_definition_name: str
    :param provisioning_state: Current state of the registration definition.
     Possible values include: 'NotSpecified', 'Accepted', 'Running', 'Ready',
     'Creating', 'Created', 'Deleting', 'Deleted', 'Canceled', 'Failed',
     'Succeeded', 'Updating'
    :type provisioning_state: str or
     ~azure.mgmt.managedservices.models.ProvisioningState
    :param managee_tenant_id: Id of the home tenant.
    :type managee_tenant_id: str
    :param managee_tenant_name: Name of the home tenant.
    :type managee_tenant_name: str
    :param managed_by_tenant_id: Id of the managedBy tenant.
    :type managed_by_tenant_id: str
    :param managed_by_tenant_name: Name of the managedBy tenant.
    :type managed_by_tenant_name: str
    """

    _attribute_map = {
        'description': {'key': 'description', 'type': 'str'},
        'authorizations': {'key': 'authorizations', 'type': '[Authorization]'},
        'eligible_authorizations': {'key': 'eligibleAuthorizations', 'type': '[EligibleAuthorization]'},
        'registration_definition_name': {'key': 'registrationDefinitionName', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'managee_tenant_id': {'key': 'manageeTenantId', 'type': 'str'},
        'managee_tenant_name': {'key': 'manageeTenantName', 'type': 'str'},
        'managed_by_tenant_id': {'key': 'managedByTenantId', 'type': 'str'},
        'managed_by_tenant_name': {'key': 'managedByTenantName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RegistrationAssignmentPropertiesRegistrationDefinitionProperties, self).__init__(**kwargs)
        self.description = kwargs.get('description', None)
        self.authorizations = kwargs.get('authorizations', None)
        self.eligible_authorizations = kwargs.get('eligible_authorizations', None)
        self.registration_definition_name = kwargs.get('registration_definition_name', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.managee_tenant_id = kwargs.get('managee_tenant_id', None)
        self.managee_tenant_name = kwargs.get('managee_tenant_name', None)
        self.managed_by_tenant_id = kwargs.get('managed_by_tenant_id', None)
        self.managed_by_tenant_name = kwargs.get('managed_by_tenant_name', None)


class RegistrationDefinition(Model):
    """Registration definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param properties: Properties of a registration definition.
    :type properties:
     ~azure.mgmt.managedservices.models.RegistrationDefinitionProperties
    :param plan: Plan details for the managed services.
    :type plan: ~azure.mgmt.managedservices.models.Plan
    :ivar id: Fully qualified path of the registration definition.
    :vartype id: str
    :ivar type: Type of the resource.
    :vartype type: str
    :ivar name: Name of the registration definition.
    :vartype name: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'RegistrationDefinitionProperties'},
        'plan': {'key': 'plan', 'type': 'Plan'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RegistrationDefinition, self).__init__(**kwargs)
        self.properties = kwargs.get('properties', None)
        self.plan = kwargs.get('plan', None)
        self.id = None
        self.type = None
        self.name = None


class RegistrationDefinitionProperties(Model):
    """Properties of a registration definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param description: Description of the registration definition.
    :type description: str
    :param authorizations: Required. Authorization tuple containing principal
     id of the user/security group or service principal and id of the build-in
     role.
    :type authorizations:
     list[~azure.mgmt.managedservices.models.Authorization]
    :param eligible_authorizations: Eligible PIM authorization tuple
     containing principal id of the user/security group or service principal,
     id of the built-in role, and just-in-time access policy setting
    :type eligible_authorizations:
     list[~azure.mgmt.managedservices.models.EligibleAuthorization]
    :param registration_definition_name: Name of the registration definition.
    :type registration_definition_name: str
    :param managed_by_tenant_id: Required. Id of the managedBy tenant.
    :type managed_by_tenant_id: str
    :ivar provisioning_state: Current state of the registration definition.
     Possible values include: 'NotSpecified', 'Accepted', 'Running', 'Ready',
     'Creating', 'Created', 'Deleting', 'Deleted', 'Canceled', 'Failed',
     'Succeeded', 'Updating'
    :vartype provisioning_state: str or
     ~azure.mgmt.managedservices.models.ProvisioningState
    :ivar managed_by_tenant_name: Name of the managedBy tenant.
    :vartype managed_by_tenant_name: str
    """

    _validation = {
        'authorizations': {'required': True},
        'managed_by_tenant_id': {'required': True},
        'provisioning_state': {'readonly': True},
        'managed_by_tenant_name': {'readonly': True},
    }

    _attribute_map = {
        'description': {'key': 'description', 'type': 'str'},
        'authorizations': {'key': 'authorizations', 'type': '[Authorization]'},
        'eligible_authorizations': {'key': 'eligibleAuthorizations', 'type': '[EligibleAuthorization]'},
        'registration_definition_name': {'key': 'registrationDefinitionName', 'type': 'str'},
        'managed_by_tenant_id': {'key': 'managedByTenantId', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'managed_by_tenant_name': {'key': 'managedByTenantName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RegistrationDefinitionProperties, self).__init__(**kwargs)
        self.description = kwargs.get('description', None)
        self.authorizations = kwargs.get('authorizations', None)
        self.eligible_authorizations = kwargs.get('eligible_authorizations', None)
        self.registration_definition_name = kwargs.get('registration_definition_name', None)
        self.managed_by_tenant_id = kwargs.get('managed_by_tenant_id', None)
        self.provisioning_state = None
        self.managed_by_tenant_name = None
