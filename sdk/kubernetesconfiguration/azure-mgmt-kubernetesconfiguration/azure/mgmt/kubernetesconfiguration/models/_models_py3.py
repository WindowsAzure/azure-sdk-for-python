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


class Resource(Model):
    """Resource.

    Common fields that are returned in the response for all Azure Resource
    Manager resources.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. E.g.
     "Microsoft.Compute/virtualMachines" or "Microsoft.Storage/storageAccounts"
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


class AzureEntityResource(Resource):
    """Entity Resource.

    The resource model definition for an Azure Resource Manager resource with
    an etag.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. E.g.
     "Microsoft.Compute/virtualMachines" or "Microsoft.Storage/storageAccounts"
    :vartype type: str
    :ivar etag: Resource Etag.
    :vartype etag: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(AzureEntityResource, self).__init__(**kwargs)
        self.etag = None


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class ComplianceStatus(Model):
    """Compliance Status details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar compliance_state: The compliance state of the configuration.
     Possible values include: 'Pending', 'Compliant', 'Noncompliant',
     'Installed', 'Failed'
    :vartype compliance_state: str or
     ~azure.mgmt.kubernetesconfiguration.models.ComplianceStateType
    :param last_config_applied: Datetime the configuration was last applied.
    :type last_config_applied: datetime
    :param message: Message from when the configuration was applied.
    :type message: str
    :param message_level: Level of the message. Possible values include:
     'Error', 'Warning', 'Information'
    :type message_level: str or
     ~azure.mgmt.kubernetesconfiguration.models.MessageLevelType
    """

    _validation = {
        'compliance_state': {'readonly': True},
    }

    _attribute_map = {
        'compliance_state': {'key': 'complianceState', 'type': 'str'},
        'last_config_applied': {'key': 'lastConfigApplied', 'type': 'iso-8601'},
        'message': {'key': 'message', 'type': 'str'},
        'message_level': {'key': 'messageLevel', 'type': 'str'},
    }

    def __init__(self, *, last_config_applied=None, message: str=None, message_level=None, **kwargs) -> None:
        super(ComplianceStatus, self).__init__(**kwargs)
        self.compliance_state = None
        self.last_config_applied = last_config_applied
        self.message = message
        self.message_level = message_level


class ErrorDefinition(Model):
    """Error definition.

    All required parameters must be populated in order to send to Azure.

    :param code: Required. Service specific error code which serves as the
     substatus for the HTTP error code.
    :type code: str
    :param message: Required. Description of the error.
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

    def __init__(self, *, code: str, message: str, **kwargs) -> None:
        super(ErrorDefinition, self).__init__(**kwargs)
        self.code = code
        self.message = message


class ErrorResponse(Model):
    """Error response.

    :param error: Error definition.
    :type error: ~azure.mgmt.kubernetesconfiguration.models.ErrorDefinition
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorDefinition'},
    }

    def __init__(self, *, error=None, **kwargs) -> None:
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = error


class ErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorResponseException, self).__init__(deserialize, response, 'ErrorResponse', *args)


class HelmOperatorProperties(Model):
    """Properties for Helm operator.

    :param chart_version: Version of the operator Helm chart.
    :type chart_version: str
    :param chart_values: Values override for the operator Helm chart.
    :type chart_values: str
    """

    _attribute_map = {
        'chart_version': {'key': 'chartVersion', 'type': 'str'},
        'chart_values': {'key': 'chartValues', 'type': 'str'},
    }

    def __init__(self, *, chart_version: str=None, chart_values: str=None, **kwargs) -> None:
        super(HelmOperatorProperties, self).__init__(**kwargs)
        self.chart_version = chart_version
        self.chart_values = chart_values


class ProxyResource(Resource):
    """Proxy Resource.

    The resource model definition for a Azure Resource Manager proxy resource.
    It will not have tags and a location.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. E.g.
     "Microsoft.Compute/virtualMachines" or "Microsoft.Storage/storageAccounts"
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
        super(ProxyResource, self).__init__(**kwargs)


class ResourceProviderOperation(Model):
    """Supported operation of this resource provider.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param name: Operation name, in format of
     {provider}/{resource}/{operation}
    :type name: str
    :param display: Display metadata associated with the operation.
    :type display:
     ~azure.mgmt.kubernetesconfiguration.models.ResourceProviderOperationDisplay
    :ivar is_data_action: The flag that indicates whether the operation
     applies to data plane.
    :vartype is_data_action: bool
    """

    _validation = {
        'is_data_action': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'ResourceProviderOperationDisplay'},
        'is_data_action': {'key': 'isDataAction', 'type': 'bool'},
    }

    def __init__(self, *, name: str=None, display=None, **kwargs) -> None:
        super(ResourceProviderOperation, self).__init__(**kwargs)
        self.name = name
        self.display = display
        self.is_data_action = None


class ResourceProviderOperationDisplay(Model):
    """Display metadata associated with the operation.

    :param provider: Resource provider: Microsoft KubernetesConfiguration.
    :type provider: str
    :param resource: Resource on which the operation is performed.
    :type resource: str
    :param operation: Type of operation: get, read, delete, etc.
    :type operation: str
    :param description: Description of this operation.
    :type description: str
    """

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self, *, provider: str=None, resource: str=None, operation: str=None, description: str=None, **kwargs) -> None:
        super(ResourceProviderOperationDisplay, self).__init__(**kwargs)
        self.provider = provider
        self.resource = resource
        self.operation = operation
        self.description = description


class Result(Model):
    """Sample result definition.

    :param sample_property: Sample property of type string
    :type sample_property: str
    """

    _attribute_map = {
        'sample_property': {'key': 'sampleProperty', 'type': 'str'},
    }

    def __init__(self, *, sample_property: str=None, **kwargs) -> None:
        super(Result, self).__init__(**kwargs)
        self.sample_property = sample_property


class SourceControlConfiguration(ProxyResource):
    """The SourceControl Configuration object returned in Get & Put response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. E.g.
     "Microsoft.Compute/virtualMachines" or "Microsoft.Storage/storageAccounts"
    :vartype type: str
    :param repository_url: Url of the SourceControl Repository.
    :type repository_url: str
    :param operator_namespace: The namespace to which this operator is
     installed to. Maximum of 253 lower case alphanumeric characters, hyphen
     and period only. Default value: "default" .
    :type operator_namespace: str
    :param operator_instance_name: Instance name of the operator - identifying
     the specific configuration.
    :type operator_instance_name: str
    :param operator_type: Type of the operator. Possible values include:
     'Flux'
    :type operator_type: str or
     ~azure.mgmt.kubernetesconfiguration.models.OperatorType
    :param operator_params: Any Parameters for the Operator instance in string
     format.
    :type operator_params: str
    :param configuration_protected_settings: Name-value pairs of protected
     configuration settings for the configuration
    :type configuration_protected_settings: dict[str, str]
    :param operator_scope: Scope at which the operator will be installed.
     Possible values include: 'cluster', 'namespace'. Default value: "cluster"
     .
    :type operator_scope: str or
     ~azure.mgmt.kubernetesconfiguration.models.OperatorScopeType
    :ivar repository_public_key: Public Key associated with this SourceControl
     configuration (either generated within the cluster or provided by the
     user).
    :vartype repository_public_key: str
    :param ssh_known_hosts_contents: Base64-encoded known_hosts contents
     containing public SSH keys required to access private Git instances
    :type ssh_known_hosts_contents: str
    :param enable_helm_operator: Option to enable Helm Operator for this git
     configuration.
    :type enable_helm_operator: bool
    :param helm_operator_properties: Properties for Helm operator.
    :type helm_operator_properties:
     ~azure.mgmt.kubernetesconfiguration.models.HelmOperatorProperties
    :ivar provisioning_state: The provisioning state of the resource provider.
     Possible values include: 'Accepted', 'Deleting', 'Running', 'Succeeded',
     'Failed'
    :vartype provisioning_state: str or
     ~azure.mgmt.kubernetesconfiguration.models.ProvisioningStateType
    :ivar compliance_status: Compliance Status of the Configuration
    :vartype compliance_status:
     ~azure.mgmt.kubernetesconfiguration.models.ComplianceStatus
    :param system_data: Top level metadata
     https://github.com/Azure/azure-resource-manager-rpc/blob/master/v1.0/common-api-contracts.md#system-metadata-for-all-azure-resources
    :type system_data: ~azure.mgmt.kubernetesconfiguration.models.SystemData
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'repository_public_key': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'compliance_status': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'repository_url': {'key': 'properties.repositoryUrl', 'type': 'str'},
        'operator_namespace': {'key': 'properties.operatorNamespace', 'type': 'str'},
        'operator_instance_name': {'key': 'properties.operatorInstanceName', 'type': 'str'},
        'operator_type': {'key': 'properties.operatorType', 'type': 'str'},
        'operator_params': {'key': 'properties.operatorParams', 'type': 'str'},
        'configuration_protected_settings': {'key': 'properties.configurationProtectedSettings', 'type': '{str}'},
        'operator_scope': {'key': 'properties.operatorScope', 'type': 'str'},
        'repository_public_key': {'key': 'properties.repositoryPublicKey', 'type': 'str'},
        'ssh_known_hosts_contents': {'key': 'properties.sshKnownHostsContents', 'type': 'str'},
        'enable_helm_operator': {'key': 'properties.enableHelmOperator', 'type': 'bool'},
        'helm_operator_properties': {'key': 'properties.helmOperatorProperties', 'type': 'HelmOperatorProperties'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'compliance_status': {'key': 'properties.complianceStatus', 'type': 'ComplianceStatus'},
        'system_data': {'key': 'systemData', 'type': 'SystemData'},
    }

    def __init__(self, *, repository_url: str=None, operator_namespace: str="default", operator_instance_name: str=None, operator_type=None, operator_params: str=None, configuration_protected_settings=None, operator_scope="cluster", ssh_known_hosts_contents: str=None, enable_helm_operator: bool=None, helm_operator_properties=None, system_data=None, **kwargs) -> None:
        super(SourceControlConfiguration, self).__init__(**kwargs)
        self.repository_url = repository_url
        self.operator_namespace = operator_namespace
        self.operator_instance_name = operator_instance_name
        self.operator_type = operator_type
        self.operator_params = operator_params
        self.configuration_protected_settings = configuration_protected_settings
        self.operator_scope = operator_scope
        self.repository_public_key = None
        self.ssh_known_hosts_contents = ssh_known_hosts_contents
        self.enable_helm_operator = enable_helm_operator
        self.helm_operator_properties = helm_operator_properties
        self.provisioning_state = None
        self.compliance_status = None
        self.system_data = system_data


class SystemData(Model):
    """Metadata pertaining to creation and last modification of the resource.

    :param created_by: The identity that created the resource.
    :type created_by: str
    :param created_by_type: The type of identity that created the resource.
     Possible values include: 'User', 'Application', 'ManagedIdentity', 'Key'
    :type created_by_type: str or
     ~azure.mgmt.kubernetesconfiguration.models.CreatedByType
    :param created_at: The timestamp of resource creation (UTC).
    :type created_at: datetime
    :param last_modified_by: The identity that last modified the resource.
    :type last_modified_by: str
    :param last_modified_by_type: The type of identity that last modified the
     resource. Possible values include: 'User', 'Application',
     'ManagedIdentity', 'Key'
    :type last_modified_by_type: str or
     ~azure.mgmt.kubernetesconfiguration.models.CreatedByType
    :param last_modified_at: The timestamp of resource last modification (UTC)
    :type last_modified_at: datetime
    """

    _attribute_map = {
        'created_by': {'key': 'createdBy', 'type': 'str'},
        'created_by_type': {'key': 'createdByType', 'type': 'str'},
        'created_at': {'key': 'createdAt', 'type': 'iso-8601'},
        'last_modified_by': {'key': 'lastModifiedBy', 'type': 'str'},
        'last_modified_by_type': {'key': 'lastModifiedByType', 'type': 'str'},
        'last_modified_at': {'key': 'lastModifiedAt', 'type': 'iso-8601'},
    }

    def __init__(self, *, created_by: str=None, created_by_type=None, created_at=None, last_modified_by: str=None, last_modified_by_type=None, last_modified_at=None, **kwargs) -> None:
        super(SystemData, self).__init__(**kwargs)
        self.created_by = created_by
        self.created_by_type = created_by_type
        self.created_at = created_at
        self.last_modified_by = last_modified_by
        self.last_modified_by_type = last_modified_by_type
        self.last_modified_at = last_modified_at


class TrackedResource(Resource):
    """Tracked Resource.

    The resource model definition for an Azure Resource Manager tracked top
    level resource which has 'tags' and a 'location'.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. E.g.
     "Microsoft.Compute/virtualMachines" or "Microsoft.Storage/storageAccounts"
    :vartype type: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives
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

    def __init__(self, *, location: str, tags=None, **kwargs) -> None:
        super(TrackedResource, self).__init__(**kwargs)
        self.tags = tags
        self.location = location
