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


class AliasPathType(Model):
    """AliasPathType.

    :param path: The path of an alias.
    :type path: str
    :param api_versions: The api versions.
    :type api_versions: list[str]
    """

    _attribute_map = {
        'path': {'key': 'path', 'type': 'str'},
        'api_versions': {'key': 'apiVersions', 'type': '[str]'},
    }

    def __init__(self, *, path: str=None, api_versions=None, **kwargs) -> None:
        super(AliasPathType, self).__init__(**kwargs)
        self.path = path
        self.api_versions = api_versions


class AliasType(Model):
    """AliasType.

    :param name: The alias name.
    :type name: str
    :param paths: The paths for an alias.
    :type paths:
     list[~azure.mgmt.resource.resources.v2016_02_01.models.AliasPathType]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'paths': {'key': 'paths', 'type': '[AliasPathType]'},
    }

    def __init__(self, *, name: str=None, paths=None, **kwargs) -> None:
        super(AliasType, self).__init__(**kwargs)
        self.name = name
        self.paths = paths


class BasicDependency(Model):
    """Deployment dependency information.

    :param id: The ID of the dependency.
    :type id: str
    :param resource_type: The dependency resource type.
    :type resource_type: str
    :param resource_name: The dependency resource name.
    :type resource_name: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'resource_type': {'key': 'resourceType', 'type': 'str'},
        'resource_name': {'key': 'resourceName', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, resource_type: str=None, resource_name: str=None, **kwargs) -> None:
        super(BasicDependency, self).__init__(**kwargs)
        self.id = id
        self.resource_type = resource_type
        self.resource_name = resource_name


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class DebugSetting(Model):
    """DebugSetting.

    :param detail_level: The debug detail level.
    :type detail_level: str
    """

    _attribute_map = {
        'detail_level': {'key': 'detailLevel', 'type': 'str'},
    }

    def __init__(self, *, detail_level: str=None, **kwargs) -> None:
        super(DebugSetting, self).__init__(**kwargs)
        self.detail_level = detail_level


class Dependency(Model):
    """Deployment dependency information.

    :param depends_on: The list of dependencies.
    :type depends_on:
     list[~azure.mgmt.resource.resources.v2016_02_01.models.BasicDependency]
    :param id: The ID of the dependency.
    :type id: str
    :param resource_type: The dependency resource type.
    :type resource_type: str
    :param resource_name: The dependency resource name.
    :type resource_name: str
    """

    _attribute_map = {
        'depends_on': {'key': 'dependsOn', 'type': '[BasicDependency]'},
        'id': {'key': 'id', 'type': 'str'},
        'resource_type': {'key': 'resourceType', 'type': 'str'},
        'resource_name': {'key': 'resourceName', 'type': 'str'},
    }

    def __init__(self, *, depends_on=None, id: str=None, resource_type: str=None, resource_name: str=None, **kwargs) -> None:
        super(Dependency, self).__init__(**kwargs)
        self.depends_on = depends_on
        self.id = id
        self.resource_type = resource_type
        self.resource_name = resource_name


class Deployment(Model):
    """Deployment operation parameters.

    :param properties: The deployment properties.
    :type properties:
     ~azure.mgmt.resource.resources.v2016_02_01.models.DeploymentProperties
    """

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'DeploymentProperties'},
    }

    def __init__(self, *, properties=None, **kwargs) -> None:
        super(Deployment, self).__init__(**kwargs)
        self.properties = properties


class DeploymentExportResult(Model):
    """DeploymentExportResult.

    :param template: The template content.
    :type template: object
    """

    _attribute_map = {
        'template': {'key': 'template', 'type': 'object'},
    }

    def __init__(self, *, template=None, **kwargs) -> None:
        super(DeploymentExportResult, self).__init__(**kwargs)
        self.template = template


class DeploymentExtended(Model):
    """Deployment information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The ID of the deployment.
    :vartype id: str
    :param name: Required. The name of the deployment.
    :type name: str
    :param properties: Deployment properties.
    :type properties:
     ~azure.mgmt.resource.resources.v2016_02_01.models.DeploymentPropertiesExtended
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'DeploymentPropertiesExtended'},
    }

    def __init__(self, *, name: str, properties=None, **kwargs) -> None:
        super(DeploymentExtended, self).__init__(**kwargs)
        self.id = None
        self.name = name
        self.properties = properties


class DeploymentExtendedFilter(Model):
    """Deployment filter.

    :param provisioning_state: The provisioning state.
    :type provisioning_state: str
    """

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
    }

    def __init__(self, *, provisioning_state: str=None, **kwargs) -> None:
        super(DeploymentExtendedFilter, self).__init__(**kwargs)
        self.provisioning_state = provisioning_state


class DeploymentOperation(Model):
    """Deployment operation information.

    :param id: Full deployment operation id.
    :type id: str
    :param operation_id: Deployment operation id.
    :type operation_id: str
    :param properties: Deployment properties.
    :type properties:
     ~azure.mgmt.resource.resources.v2016_02_01.models.DeploymentOperationProperties
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'operation_id': {'key': 'operationId', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'DeploymentOperationProperties'},
    }

    def __init__(self, *, id: str=None, operation_id: str=None, properties=None, **kwargs) -> None:
        super(DeploymentOperation, self).__init__(**kwargs)
        self.id = id
        self.operation_id = operation_id
        self.properties = properties


class DeploymentOperationProperties(Model):
    """Deployment operation properties.

    :param provisioning_state: The state of the provisioning.
    :type provisioning_state: str
    :param timestamp: The date and time of the operation.
    :type timestamp: datetime
    :param service_request_id: Deployment operation service request id.
    :type service_request_id: str
    :param status_code: Operation status code.
    :type status_code: str
    :param status_message: Operation status message.
    :type status_message: object
    :param target_resource: The target resource.
    :type target_resource:
     ~azure.mgmt.resource.resources.v2016_02_01.models.TargetResource
    :param request: The HTTP request message.
    :type request:
     ~azure.mgmt.resource.resources.v2016_02_01.models.HttpMessage
    :param response: The HTTP response message.
    :type response:
     ~azure.mgmt.resource.resources.v2016_02_01.models.HttpMessage
    """

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'service_request_id': {'key': 'serviceRequestId', 'type': 'str'},
        'status_code': {'key': 'statusCode', 'type': 'str'},
        'status_message': {'key': 'statusMessage', 'type': 'object'},
        'target_resource': {'key': 'targetResource', 'type': 'TargetResource'},
        'request': {'key': 'request', 'type': 'HttpMessage'},
        'response': {'key': 'response', 'type': 'HttpMessage'},
    }

    def __init__(self, *, provisioning_state: str=None, timestamp=None, service_request_id: str=None, status_code: str=None, status_message=None, target_resource=None, request=None, response=None, **kwargs) -> None:
        super(DeploymentOperationProperties, self).__init__(**kwargs)
        self.provisioning_state = provisioning_state
        self.timestamp = timestamp
        self.service_request_id = service_request_id
        self.status_code = status_code
        self.status_message = status_message
        self.target_resource = target_resource
        self.request = request
        self.response = response


class DeploymentProperties(Model):
    """Deployment properties.

    All required parameters must be populated in order to send to Azure.

    :param template: The template content. It can be a JObject or a well
     formed JSON string. Use only one of Template or TemplateLink.
    :type template: object
    :param template_link: The template URI. Use only one of Template or
     TemplateLink.
    :type template_link:
     ~azure.mgmt.resource.resources.v2016_02_01.models.TemplateLink
    :param parameters: Deployment parameters. It can be a JObject or a well
     formed JSON string. Use only one of Parameters or ParametersLink.
    :type parameters: object
    :param parameters_link: The parameters URI. Use only one of Parameters or
     ParametersLink.
    :type parameters_link:
     ~azure.mgmt.resource.resources.v2016_02_01.models.ParametersLink
    :param mode: Required. The deployment mode. Possible values include:
     'Incremental', 'Complete'
    :type mode: str or
     ~azure.mgmt.resource.resources.v2016_02_01.models.DeploymentMode
    :param debug_setting: The debug setting of the deployment.
    :type debug_setting:
     ~azure.mgmt.resource.resources.v2016_02_01.models.DebugSetting
    """

    _validation = {
        'mode': {'required': True},
    }

    _attribute_map = {
        'template': {'key': 'template', 'type': 'object'},
        'template_link': {'key': 'templateLink', 'type': 'TemplateLink'},
        'parameters': {'key': 'parameters', 'type': 'object'},
        'parameters_link': {'key': 'parametersLink', 'type': 'ParametersLink'},
        'mode': {'key': 'mode', 'type': 'DeploymentMode'},
        'debug_setting': {'key': 'debugSetting', 'type': 'DebugSetting'},
    }

    def __init__(self, *, mode, template=None, template_link=None, parameters=None, parameters_link=None, debug_setting=None, **kwargs) -> None:
        super(DeploymentProperties, self).__init__(**kwargs)
        self.template = template
        self.template_link = template_link
        self.parameters = parameters
        self.parameters_link = parameters_link
        self.mode = mode
        self.debug_setting = debug_setting


class DeploymentPropertiesExtended(Model):
    """Deployment properties with additional details.

    :param provisioning_state: The state of the provisioning.
    :type provisioning_state: str
    :param correlation_id: The correlation ID of the deployment.
    :type correlation_id: str
    :param timestamp: The timestamp of the template deployment.
    :type timestamp: datetime
    :param outputs: Key/value pairs that represent deployment output.
    :type outputs: object
    :param providers: The list of resource providers needed for the
     deployment.
    :type providers:
     list[~azure.mgmt.resource.resources.v2016_02_01.models.Provider]
    :param dependencies: The list of deployment dependencies.
    :type dependencies:
     list[~azure.mgmt.resource.resources.v2016_02_01.models.Dependency]
    :param template: The template content. Use only one of Template or
     TemplateLink.
    :type template: object
    :param template_link: The URI referencing the template. Use only one of
     Template or TemplateLink.
    :type template_link:
     ~azure.mgmt.resource.resources.v2016_02_01.models.TemplateLink
    :param parameters: Deployment parameters. Use only one of Parameters or
     ParametersLink.
    :type parameters: object
    :param parameters_link: The URI referencing the parameters. Use only one
     of Parameters or ParametersLink.
    :type parameters_link:
     ~azure.mgmt.resource.resources.v2016_02_01.models.ParametersLink
    :param mode: The deployment mode. Possible values include: 'Incremental',
     'Complete'
    :type mode: str or
     ~azure.mgmt.resource.resources.v2016_02_01.models.DeploymentMode
    :param debug_setting: The debug setting of the deployment.
    :type debug_setting:
     ~azure.mgmt.resource.resources.v2016_02_01.models.DebugSetting
    """

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'correlation_id': {'key': 'correlationId', 'type': 'str'},
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'outputs': {'key': 'outputs', 'type': 'object'},
        'providers': {'key': 'providers', 'type': '[Provider]'},
        'dependencies': {'key': 'dependencies', 'type': '[Dependency]'},
        'template': {'key': 'template', 'type': 'object'},
        'template_link': {'key': 'templateLink', 'type': 'TemplateLink'},
        'parameters': {'key': 'parameters', 'type': 'object'},
        'parameters_link': {'key': 'parametersLink', 'type': 'ParametersLink'},
        'mode': {'key': 'mode', 'type': 'DeploymentMode'},
        'debug_setting': {'key': 'debugSetting', 'type': 'DebugSetting'},
    }

    def __init__(self, *, provisioning_state: str=None, correlation_id: str=None, timestamp=None, outputs=None, providers=None, dependencies=None, template=None, template_link=None, parameters=None, parameters_link=None, mode=None, debug_setting=None, **kwargs) -> None:
        super(DeploymentPropertiesExtended, self).__init__(**kwargs)
        self.provisioning_state = provisioning_state
        self.correlation_id = correlation_id
        self.timestamp = timestamp
        self.outputs = outputs
        self.providers = providers
        self.dependencies = dependencies
        self.template = template
        self.template_link = template_link
        self.parameters = parameters
        self.parameters_link = parameters_link
        self.mode = mode
        self.debug_setting = debug_setting


class DeploymentValidateResult(Model):
    """Information from validate template deployment response.

    :param error: Validation error.
    :type error:
     ~azure.mgmt.resource.resources.v2016_02_01.models.ResourceManagementErrorWithDetails
    :param properties: The template deployment properties.
    :type properties:
     ~azure.mgmt.resource.resources.v2016_02_01.models.DeploymentPropertiesExtended
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ResourceManagementErrorWithDetails'},
        'properties': {'key': 'properties', 'type': 'DeploymentPropertiesExtended'},
    }

    def __init__(self, *, error=None, properties=None, **kwargs) -> None:
        super(DeploymentValidateResult, self).__init__(**kwargs)
        self.error = error
        self.properties = properties


class ExportTemplateRequest(Model):
    """Export resource group template request parameters.

    :param resources: The IDs of the resources to filter the export by. To
     export all resources, supply an array with single entry '*'.
    :type resources: list[str]
    :param options: The export template options. A CSV-formatted list
     containing zero or more of the following: 'IncludeParameterDefaultValue',
     'IncludeComments', 'SkipResourceNameParameterization',
     'SkipAllParameterization'
    :type options: str
    """

    _attribute_map = {
        'resources': {'key': 'resources', 'type': '[str]'},
        'options': {'key': 'options', 'type': 'str'},
    }

    def __init__(self, *, resources=None, options: str=None, **kwargs) -> None:
        super(ExportTemplateRequest, self).__init__(**kwargs)
        self.resources = resources
        self.options = options


class Resource(Model):
    """Resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
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
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = location
        self.tags = tags


class GenericResource(Resource):
    """Resource information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param plan: The plan of the resource.
    :type plan: ~azure.mgmt.resource.resources.v2016_02_01.models.Plan
    :param properties: The resource properties.
    :type properties: object
    :param kind: The kind of the resource.
    :type kind: str
    :param managed_by: Id of the resource that manages this resource.
    :type managed_by: str
    :param sku: The sku of the resource.
    :type sku: ~azure.mgmt.resource.resources.v2016_02_01.models.Sku
    :param identity: The identity of the resource.
    :type identity: ~azure.mgmt.resource.resources.v2016_02_01.models.Identity
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
        'plan': {'key': 'plan', 'type': 'Plan'},
        'properties': {'key': 'properties', 'type': 'object'},
        'kind': {'key': 'kind', 'type': 'str'},
        'managed_by': {'key': 'managedBy', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'identity': {'key': 'identity', 'type': 'Identity'},
    }

    def __init__(self, *, location: str=None, tags=None, plan=None, properties=None, kind: str=None, managed_by: str=None, sku=None, identity=None, **kwargs) -> None:
        super(GenericResource, self).__init__(location=location, tags=tags, **kwargs)
        self.plan = plan
        self.properties = properties
        self.kind = kind
        self.managed_by = managed_by
        self.sku = sku
        self.identity = identity


class GenericResourceFilter(Model):
    """Resource filter.

    :param resource_type: The resource type.
    :type resource_type: str
    :param tagname: The tag name.
    :type tagname: str
    :param tagvalue: The tag value.
    :type tagvalue: str
    """

    _attribute_map = {
        'resource_type': {'key': 'resourceType', 'type': 'str'},
        'tagname': {'key': 'tagname', 'type': 'str'},
        'tagvalue': {'key': 'tagvalue', 'type': 'str'},
    }

    def __init__(self, *, resource_type: str=None, tagname: str=None, tagvalue: str=None, **kwargs) -> None:
        super(GenericResourceFilter, self).__init__(**kwargs)
        self.resource_type = resource_type
        self.tagname = tagname
        self.tagvalue = tagvalue


class HttpMessage(Model):
    """HttpMessage.

    :param content: HTTP message content.
    :type content: object
    """

    _attribute_map = {
        'content': {'key': 'content', 'type': 'object'},
    }

    def __init__(self, *, content=None, **kwargs) -> None:
        super(HttpMessage, self).__init__(**kwargs)
        self.content = content


class Identity(Model):
    """Identity for the resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar principal_id: The principal id of resource identity.
    :vartype principal_id: str
    :ivar tenant_id: The tenant id of resource.
    :vartype tenant_id: str
    :param type: The identity type. Possible values include: 'SystemAssigned'
    :type type: str or
     ~azure.mgmt.resource.resources.v2016_02_01.models.ResourceIdentityType
    """

    _validation = {
        'principal_id': {'readonly': True},
        'tenant_id': {'readonly': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'ResourceIdentityType'},
    }

    def __init__(self, *, type=None, **kwargs) -> None:
        super(Identity, self).__init__(**kwargs)
        self.principal_id = None
        self.tenant_id = None
        self.type = type


class ParametersLink(Model):
    """Entity representing the reference to the deployment parameters.

    All required parameters must be populated in order to send to Azure.

    :param uri: Required. URI referencing the template.
    :type uri: str
    :param content_version: If included it must match the ContentVersion in
     the template.
    :type content_version: str
    """

    _validation = {
        'uri': {'required': True},
    }

    _attribute_map = {
        'uri': {'key': 'uri', 'type': 'str'},
        'content_version': {'key': 'contentVersion', 'type': 'str'},
    }

    def __init__(self, *, uri: str, content_version: str=None, **kwargs) -> None:
        super(ParametersLink, self).__init__(**kwargs)
        self.uri = uri
        self.content_version = content_version


class Plan(Model):
    """Plan for the resource.

    :param name: The plan ID.
    :type name: str
    :param publisher: The publisher ID.
    :type publisher: str
    :param product: The offer ID.
    :type product: str
    :param promotion_code: The promotion code.
    :type promotion_code: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'publisher': {'key': 'publisher', 'type': 'str'},
        'product': {'key': 'product', 'type': 'str'},
        'promotion_code': {'key': 'promotionCode', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, publisher: str=None, product: str=None, promotion_code: str=None, **kwargs) -> None:
        super(Plan, self).__init__(**kwargs)
        self.name = name
        self.publisher = publisher
        self.product = product
        self.promotion_code = promotion_code


class Provider(Model):
    """Resource provider information.

    :param id: The provider id.
    :type id: str
    :param namespace: The namespace of the provider.
    :type namespace: str
    :param registration_state: The registration state of the provider.
    :type registration_state: str
    :param resource_types: The collection of provider resource types.
    :type resource_types:
     list[~azure.mgmt.resource.resources.v2016_02_01.models.ProviderResourceType]
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'namespace': {'key': 'namespace', 'type': 'str'},
        'registration_state': {'key': 'registrationState', 'type': 'str'},
        'resource_types': {'key': 'resourceTypes', 'type': '[ProviderResourceType]'},
    }

    def __init__(self, *, id: str=None, namespace: str=None, registration_state: str=None, resource_types=None, **kwargs) -> None:
        super(Provider, self).__init__(**kwargs)
        self.id = id
        self.namespace = namespace
        self.registration_state = registration_state
        self.resource_types = resource_types


class ProviderResourceType(Model):
    """Resource type managed by the resource provider.

    :param resource_type: The resource type.
    :type resource_type: str
    :param locations: The collection of locations where this resource type can
     be created in.
    :type locations: list[str]
    :param aliases: The aliases that are supported by this resource type.
    :type aliases:
     list[~azure.mgmt.resource.resources.v2016_02_01.models.AliasType]
    :param api_versions: The api version.
    :type api_versions: list[str]
    :param properties: The properties.
    :type properties: dict[str, str]
    """

    _attribute_map = {
        'resource_type': {'key': 'resourceType', 'type': 'str'},
        'locations': {'key': 'locations', 'type': '[str]'},
        'aliases': {'key': 'aliases', 'type': '[AliasType]'},
        'api_versions': {'key': 'apiVersions', 'type': '[str]'},
        'properties': {'key': 'properties', 'type': '{str}'},
    }

    def __init__(self, *, resource_type: str=None, locations=None, aliases=None, api_versions=None, properties=None, **kwargs) -> None:
        super(ProviderResourceType, self).__init__(**kwargs)
        self.resource_type = resource_type
        self.locations = locations
        self.aliases = aliases
        self.api_versions = api_versions
        self.properties = properties


class ResourceGroup(Model):
    """Resource group information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The ID of the resource group.
    :vartype id: str
    :param name: The Name of the resource group.
    :type name: str
    :param properties:
    :type properties:
     ~azure.mgmt.resource.resources.v2016_02_01.models.ResourceGroupProperties
    :param location: Required. The location of the resource group. It cannot
     be changed after the resource group has been created. Has to be one of the
     supported Azure Locations, such as West US, East US, West Europe, East
     Asia, etc.
    :type location: str
    :param tags: The tags attached to the resource group.
    :type tags: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'ResourceGroupProperties'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, location: str, name: str=None, properties=None, tags=None, **kwargs) -> None:
        super(ResourceGroup, self).__init__(**kwargs)
        self.id = None
        self.name = name
        self.properties = properties
        self.location = location
        self.tags = tags


class ResourceGroupExportResult(Model):
    """ResourceGroupExportResult.

    :param template: The template content.
    :type template: object
    :param error: The error.
    :type error:
     ~azure.mgmt.resource.resources.v2016_02_01.models.ResourceManagementErrorWithDetails
    """

    _attribute_map = {
        'template': {'key': 'template', 'type': 'object'},
        'error': {'key': 'error', 'type': 'ResourceManagementErrorWithDetails'},
    }

    def __init__(self, *, template=None, error=None, **kwargs) -> None:
        super(ResourceGroupExportResult, self).__init__(**kwargs)
        self.template = template
        self.error = error


class ResourceGroupFilter(Model):
    """Resource group filter.

    :param tag_name: The tag name.
    :type tag_name: str
    :param tag_value: The tag value.
    :type tag_value: str
    """

    _attribute_map = {
        'tag_name': {'key': 'tagName', 'type': 'str'},
        'tag_value': {'key': 'tagValue', 'type': 'str'},
    }

    def __init__(self, *, tag_name: str=None, tag_value: str=None, **kwargs) -> None:
        super(ResourceGroupFilter, self).__init__(**kwargs)
        self.tag_name = tag_name
        self.tag_value = tag_value


class ResourceGroupProperties(Model):
    """The resource group properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provisioning_state: The provisioning state.
    :vartype provisioning_state: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(ResourceGroupProperties, self).__init__(**kwargs)
        self.provisioning_state = None


class ResourceManagementErrorWithDetails(Model):
    """ResourceManagementErrorWithDetails.

    All required parameters must be populated in order to send to Azure.

    :param code: Required. The error code returned from the server.
    :type code: str
    :param message: Required. The error message returned from the server.
    :type message: str
    :param target: The target of the error.
    :type target: str
    :param details: Validation error.
    :type details:
     list[~azure.mgmt.resource.resources.v2016_02_01.models.ResourceManagementErrorWithDetails]
    """

    _validation = {
        'code': {'required': True},
        'message': {'required': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ResourceManagementErrorWithDetails]'},
    }

    def __init__(self, *, code: str, message: str, target: str=None, details=None, **kwargs) -> None:
        super(ResourceManagementErrorWithDetails, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.target = target
        self.details = details


class ResourceProviderOperationDisplayProperties(Model):
    """Resource provider operation's display properties.

    :param publisher: Operation description.
    :type publisher: str
    :param provider: Operation provider.
    :type provider: str
    :param resource: Operation resource.
    :type resource: str
    :param operation: Operation.
    :type operation: str
    :param description: Operation description.
    :type description: str
    """

    _attribute_map = {
        'publisher': {'key': 'publisher', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self, *, publisher: str=None, provider: str=None, resource: str=None, operation: str=None, description: str=None, **kwargs) -> None:
        super(ResourceProviderOperationDisplayProperties, self).__init__(**kwargs)
        self.publisher = publisher
        self.provider = provider
        self.resource = resource
        self.operation = operation
        self.description = description


class ResourcesMoveInfo(Model):
    """Parameters of move resources.

    :param resources: The ids of the resources.
    :type resources: list[str]
    :param target_resource_group: The target resource group.
    :type target_resource_group: str
    """

    _attribute_map = {
        'resources': {'key': 'resources', 'type': '[str]'},
        'target_resource_group': {'key': 'targetResourceGroup', 'type': 'str'},
    }

    def __init__(self, *, resources=None, target_resource_group: str=None, **kwargs) -> None:
        super(ResourcesMoveInfo, self).__init__(**kwargs)
        self.resources = resources
        self.target_resource_group = target_resource_group


class Sku(Model):
    """Sku for the resource.

    :param name: The sku name.
    :type name: str
    :param tier: The sku tier.
    :type tier: str
    :param size: The sku size.
    :type size: str
    :param family: The sku family.
    :type family: str
    :param model: The sku model.
    :type model: str
    :param capacity: The sku capacity.
    :type capacity: int
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'size': {'key': 'size', 'type': 'str'},
        'family': {'key': 'family', 'type': 'str'},
        'model': {'key': 'model', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(self, *, name: str=None, tier: str=None, size: str=None, family: str=None, model: str=None, capacity: int=None, **kwargs) -> None:
        super(Sku, self).__init__(**kwargs)
        self.name = name
        self.tier = tier
        self.size = size
        self.family = family
        self.model = model
        self.capacity = capacity


class SubResource(Model):
    """SubResource.

    :param id: Resource Id
    :type id: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, **kwargs) -> None:
        super(SubResource, self).__init__(**kwargs)
        self.id = id


class TagCount(Model):
    """Tag count.

    :param type: Type of count.
    :type type: str
    :param value: Value of count.
    :type value: str
    """

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, *, type: str=None, value: str=None, **kwargs) -> None:
        super(TagCount, self).__init__(**kwargs)
        self.type = type
        self.value = value


class TagDetails(Model):
    """Tag details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The tag ID.
    :vartype id: str
    :param tag_name: The tag name.
    :type tag_name: str
    :param count: The tag count.
    :type count: ~azure.mgmt.resource.resources.v2016_02_01.models.TagCount
    :param values: The list of tag values.
    :type values:
     list[~azure.mgmt.resource.resources.v2016_02_01.models.TagValue]
    """

    _validation = {
        'id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'tag_name': {'key': 'tagName', 'type': 'str'},
        'count': {'key': 'count', 'type': 'TagCount'},
        'values': {'key': 'values', 'type': '[TagValue]'},
    }

    def __init__(self, *, tag_name: str=None, count=None, values=None, **kwargs) -> None:
        super(TagDetails, self).__init__(**kwargs)
        self.id = None
        self.tag_name = tag_name
        self.count = count
        self.values = values


class TagValue(Model):
    """Tag information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The tag ID.
    :vartype id: str
    :param tag_value: The tag value.
    :type tag_value: str
    :param count: The tag value count.
    :type count: ~azure.mgmt.resource.resources.v2016_02_01.models.TagCount
    """

    _validation = {
        'id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'tag_value': {'key': 'tagValue', 'type': 'str'},
        'count': {'key': 'count', 'type': 'TagCount'},
    }

    def __init__(self, *, tag_value: str=None, count=None, **kwargs) -> None:
        super(TagValue, self).__init__(**kwargs)
        self.id = None
        self.tag_value = tag_value
        self.count = count


class TargetResource(Model):
    """Target resource.

    :param id: The ID of the resource.
    :type id: str
    :param resource_name: The name of the resource.
    :type resource_name: str
    :param resource_type: The type of the resource.
    :type resource_type: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'resource_name': {'key': 'resourceName', 'type': 'str'},
        'resource_type': {'key': 'resourceType', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, resource_name: str=None, resource_type: str=None, **kwargs) -> None:
        super(TargetResource, self).__init__(**kwargs)
        self.id = id
        self.resource_name = resource_name
        self.resource_type = resource_type


class TemplateLink(Model):
    """Entity representing the reference to the template.

    All required parameters must be populated in order to send to Azure.

    :param uri: Required. URI referencing the template.
    :type uri: str
    :param content_version: If included it must match the ContentVersion in
     the template.
    :type content_version: str
    """

    _validation = {
        'uri': {'required': True},
    }

    _attribute_map = {
        'uri': {'key': 'uri', 'type': 'str'},
        'content_version': {'key': 'contentVersion', 'type': 'str'},
    }

    def __init__(self, *, uri: str, content_version: str=None, **kwargs) -> None:
        super(TemplateLink, self).__init__(**kwargs)
        self.uri = uri
        self.content_version = content_version
