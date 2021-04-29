# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import msrest.serialization


class AccountKeyRegenerateRequest(msrest.serialization.Model):
    """Request for account key regeneration.

    :param serial: Serial of key to be regenerated. Possible values include: 1, 2. Default value:
     "1".
    :type serial: str or ~azure.mgmt.mixedreality.models.Serial
    """

    _attribute_map = {
        'serial': {'key': 'serial', 'type': 'int'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AccountKeyRegenerateRequest, self).__init__(**kwargs)
        self.serial = kwargs.get('serial', "1")


class AccountKeys(msrest.serialization.Model):
    """Developer Keys of account.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar primary_key: value of primary key.
    :vartype primary_key: str
    :ivar secondary_key: value of secondary key.
    :vartype secondary_key: str
    """

    _validation = {
        'primary_key': {'readonly': True},
        'secondary_key': {'readonly': True},
    }

    _attribute_map = {
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AccountKeys, self).__init__(**kwargs)
        self.primary_key = None
        self.secondary_key = None


class CheckNameAvailabilityRequest(msrest.serialization.Model):
    """Check Name Availability Request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Resource Name To Verify.
    :type name: str
    :param type: Required. Fully qualified resource type which includes provider namespace.
    :type type: str
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CheckNameAvailabilityRequest, self).__init__(**kwargs)
        self.name = kwargs['name']
        self.type = kwargs['type']


class CheckNameAvailabilityResponse(msrest.serialization.Model):
    """Check Name Availability Response.

    All required parameters must be populated in order to send to Azure.

    :param name_available: Required. if name Available.
    :type name_available: bool
    :param reason: Resource Name To Verify. Possible values include: "Invalid", "AlreadyExists".
    :type reason: str or ~azure.mgmt.mixedreality.models.NameUnavailableReason
    :param message: detail message.
    :type message: str
    """

    _validation = {
        'name_available': {'required': True},
    }

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CheckNameAvailabilityResponse, self).__init__(**kwargs)
        self.name_available = kwargs['name_available']
        self.reason = kwargs.get('reason', None)
        self.message = kwargs.get('message', None)


class CloudErrorBody(msrest.serialization.Model):
    """An error response from Azure.

    :param code: An identifier for the error. Codes are invariant and are intended to be consumed
     programmatically.
    :type code: str
    :param message: A message describing the error, intended to be suitable for displaying in a
     user interface.
    :type message: str
    :param target: The target of the particular error. For example, the name of the property in
     error.
    :type target: str
    :param details: A list of additional details about the error.
    :type details: list[~azure.mgmt.mixedreality.models.CloudErrorBody]
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[CloudErrorBody]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CloudErrorBody, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)
        self.target = kwargs.get('target', None)
        self.details = kwargs.get('details', None)


class Identity(msrest.serialization.Model):
    """Identity for the resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar principal_id: The principal ID of resource identity.
    :vartype principal_id: str
    :ivar tenant_id: The tenant ID of resource.
    :vartype tenant_id: str
    :ivar type: The identity type. Default value: "SystemAssigned".
    :vartype type: str
    """

    _validation = {
        'principal_id': {'readonly': True},
        'tenant_id': {'readonly': True},
        'type': {'constant': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    type = "SystemAssigned"

    def __init__(
        self,
        **kwargs
    ):
        super(Identity, self).__init__(**kwargs)
        self.principal_id = None
        self.tenant_id = None


class LogSpecification(msrest.serialization.Model):
    """Specifications of the Log for Azure Monitoring.

    :param name: Name of the log.
    :type name: str
    :param display_name: Localized friendly display name of the log.
    :type display_name: str
    :param blob_duration: Blob duration of the log.
    :type blob_duration: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'blob_duration': {'key': 'blobDuration', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LogSpecification, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display_name = kwargs.get('display_name', None)
        self.blob_duration = kwargs.get('blob_duration', None)


class MetricDimension(msrest.serialization.Model):
    """Specifications of the Dimension of metrics.

    :param name: Name of the dimension.
    :type name: str
    :param display_name: Localized friendly display name of the dimension.
    :type display_name: str
    :param internal_name: Internal name of the dimension.
    :type internal_name: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'internal_name': {'key': 'internalName', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MetricDimension, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display_name = kwargs.get('display_name', None)
        self.internal_name = kwargs.get('internal_name', None)


class MetricSpecification(msrest.serialization.Model):
    """Specifications of the Metrics for Azure Monitoring.

    :param name: Name of the metric.
    :type name: str
    :param display_name: Localized friendly display name of the metric.
    :type display_name: str
    :param display_description: Localized friendly description of the metric.
    :type display_description: str
    :param unit: Unit that makes sense for the metric.
    :type unit: str
    :param aggregation_type: Only provide one value for this field. Valid values: Average, Minimum,
     Maximum, Total, Count.
    :type aggregation_type: str
    :param internal_metric_name: Internal metric name.
    :type internal_metric_name: str
    :param dimensions: Dimensions of the metric.
    :type dimensions: list[~azure.mgmt.mixedreality.models.MetricDimension]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'display_description': {'key': 'displayDescription', 'type': 'str'},
        'unit': {'key': 'unit', 'type': 'str'},
        'aggregation_type': {'key': 'aggregationType', 'type': 'str'},
        'internal_metric_name': {'key': 'internalMetricName', 'type': 'str'},
        'dimensions': {'key': 'dimensions', 'type': '[MetricDimension]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MetricSpecification, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display_name = kwargs.get('display_name', None)
        self.display_description = kwargs.get('display_description', None)
        self.unit = kwargs.get('unit', None)
        self.aggregation_type = kwargs.get('aggregation_type', None)
        self.internal_metric_name = kwargs.get('internal_metric_name', None)
        self.dimensions = kwargs.get('dimensions', None)


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


class ObjectAnchorsAccount(TrackedResource):
    """ObjectAnchorsAccount Response.

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
    :param identity:
    :type identity: ~azure.mgmt.mixedreality.models.ObjectAnchorsAccountIdentity
    :ivar system_data: The system metadata related to an object anchors account.
    :vartype system_data: ~azure.mgmt.mixedreality.models.SystemData
    :param storage_account_name: The name of the storage account associated with this accountId.
    :type storage_account_name: str
    :ivar account_id: unique id of certain account.
    :vartype account_id: str
    :ivar account_domain: Correspond domain name of certain Spatial Anchors Account.
    :vartype account_domain: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'system_data': {'readonly': True},
        'account_id': {'readonly': True},
        'account_domain': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'ObjectAnchorsAccountIdentity'},
        'system_data': {'key': 'systemData', 'type': 'SystemData'},
        'storage_account_name': {'key': 'properties.storageAccountName', 'type': 'str'},
        'account_id': {'key': 'properties.accountId', 'type': 'str'},
        'account_domain': {'key': 'properties.accountDomain', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ObjectAnchorsAccount, self).__init__(**kwargs)
        self.identity = kwargs.get('identity', None)
        self.system_data = None
        self.storage_account_name = kwargs.get('storage_account_name', None)
        self.account_id = None
        self.account_domain = None


class ObjectAnchorsAccountIdentity(Identity):
    """ObjectAnchorsAccountIdentity.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar principal_id: The principal ID of resource identity.
    :vartype principal_id: str
    :ivar tenant_id: The tenant ID of resource.
    :vartype tenant_id: str
    :ivar type: The identity type. Default value: "SystemAssigned".
    :vartype type: str
    """

    _validation = {
        'principal_id': {'readonly': True},
        'tenant_id': {'readonly': True},
        'type': {'constant': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    type = "SystemAssigned"

    def __init__(
        self,
        **kwargs
    ):
        super(ObjectAnchorsAccountIdentity, self).__init__(**kwargs)


class ObjectAnchorsAccountPage(msrest.serialization.Model):
    """Result of the request to get resource collection. It contains a list of resources and a URL link to get the next set of results.

    :param value: List of resources supported by the Resource Provider.
    :type value: list[~azure.mgmt.mixedreality.models.ObjectAnchorsAccount]
    :param next_link: URL to get the next set of resource list results if there are any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ObjectAnchorsAccount]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ObjectAnchorsAccountPage, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)


class Operation(msrest.serialization.Model):
    """REST API operation.

    :param name: Operation name: {provider}/{resource}/{operation}.
    :type name: str
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.mixedreality.models.OperationDisplay
    :param is_data_action: Whether or not this is a data plane operation.
    :type is_data_action: bool
    :param origin: The origin.
    :type origin: str
    :param properties: Properties of the operation.
    :type properties: ~azure.mgmt.mixedreality.models.OperationProperties
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
        'is_data_action': {'key': 'isDataAction', 'type': 'bool'},
        'origin': {'key': 'origin', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'OperationProperties'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Operation, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display = kwargs.get('display', None)
        self.is_data_action = kwargs.get('is_data_action', None)
        self.origin = kwargs.get('origin', None)
        self.properties = kwargs.get('properties', None)


class OperationDisplay(msrest.serialization.Model):
    """The object that represents the operation.

    All required parameters must be populated in order to send to Azure.

    :param provider: Required. Service provider: Microsoft.ResourceProvider.
    :type provider: str
    :param resource: Required. Resource on which the operation is performed: Profile, endpoint,
     etc.
    :type resource: str
    :param operation: Required. Operation type: Read, write, delete, etc.
    :type operation: str
    :param description: Required. Description of operation.
    :type description: str
    """

    _validation = {
        'provider': {'required': True},
        'resource': {'required': True},
        'operation': {'required': True},
        'description': {'required': True},
    }

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
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = kwargs['provider']
        self.resource = kwargs['resource']
        self.operation = kwargs['operation']
        self.description = kwargs['description']


class OperationPage(msrest.serialization.Model):
    """Result of the request to list Resource Provider operations. It contains a list of operations and a URL link to get the next set of results.

    :param value: List of operations supported by the Resource Provider.
    :type value: list[~azure.mgmt.mixedreality.models.Operation]
    :param next_link: URL to get the next set of operation list results if there are any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Operation]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationPage, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)


class OperationProperties(msrest.serialization.Model):
    """Operation properties.

    :param service_specification: Service specification.
    :type service_specification: ~azure.mgmt.mixedreality.models.ServiceSpecification
    """

    _attribute_map = {
        'service_specification': {'key': 'serviceSpecification', 'type': 'ServiceSpecification'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationProperties, self).__init__(**kwargs)
        self.service_specification = kwargs.get('service_specification', None)


class RemoteRenderingAccount(TrackedResource):
    """RemoteRenderingAccount Response.

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
    :param identity: The identity associated with this account.
    :type identity: ~azure.mgmt.mixedreality.models.Identity
    :param plan: The plan associated with this account.
    :type plan: ~azure.mgmt.mixedreality.models.Identity
    :param sku: The sku associated with this account.
    :type sku: ~azure.mgmt.mixedreality.models.Sku
    :param kind: The kind of account, if supported.
    :type kind: ~azure.mgmt.mixedreality.models.Sku
    :ivar system_data: System metadata for this account.
    :vartype system_data: ~azure.mgmt.mixedreality.models.SystemData
    :param storage_account_name: The name of the storage account associated with this accountId.
    :type storage_account_name: str
    :ivar account_id: unique id of certain account.
    :vartype account_id: str
    :ivar account_domain: Correspond domain name of certain Spatial Anchors Account.
    :vartype account_domain: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'system_data': {'readonly': True},
        'account_id': {'readonly': True},
        'account_domain': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'Identity'},
        'plan': {'key': 'plan', 'type': 'Identity'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'kind': {'key': 'kind', 'type': 'Sku'},
        'system_data': {'key': 'systemData', 'type': 'SystemData'},
        'storage_account_name': {'key': 'properties.storageAccountName', 'type': 'str'},
        'account_id': {'key': 'properties.accountId', 'type': 'str'},
        'account_domain': {'key': 'properties.accountDomain', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RemoteRenderingAccount, self).__init__(**kwargs)
        self.identity = kwargs.get('identity', None)
        self.plan = kwargs.get('plan', None)
        self.sku = kwargs.get('sku', None)
        self.kind = kwargs.get('kind', None)
        self.system_data = None
        self.storage_account_name = kwargs.get('storage_account_name', None)
        self.account_id = None
        self.account_domain = None


class RemoteRenderingAccountPage(msrest.serialization.Model):
    """Result of the request to get resource collection. It contains a list of resources and a URL link to get the next set of results.

    :param value: List of resources supported by the Resource Provider.
    :type value: list[~azure.mgmt.mixedreality.models.RemoteRenderingAccount]
    :param next_link: URL to get the next set of resource list results if there are any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[RemoteRenderingAccount]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RemoteRenderingAccountPage, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)


class ServiceSpecification(msrest.serialization.Model):
    """Service specification payload.

    :param log_specifications: Specifications of the Log for Azure Monitoring.
    :type log_specifications: list[~azure.mgmt.mixedreality.models.LogSpecification]
    :param metric_specifications: Specifications of the Metrics for Azure Monitoring.
    :type metric_specifications: list[~azure.mgmt.mixedreality.models.MetricSpecification]
    """

    _attribute_map = {
        'log_specifications': {'key': 'logSpecifications', 'type': '[LogSpecification]'},
        'metric_specifications': {'key': 'metricSpecifications', 'type': '[MetricSpecification]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ServiceSpecification, self).__init__(**kwargs)
        self.log_specifications = kwargs.get('log_specifications', None)
        self.metric_specifications = kwargs.get('metric_specifications', None)


class Sku(msrest.serialization.Model):
    """The resource model definition representing SKU.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the SKU. Ex - P3. It is typically a letter+number code.
    :type name: str
    :param tier: This field is required to be implemented by the Resource Provider if the service
     has more than one tier, but is not required on a PUT. Possible values include: "Free", "Basic",
     "Standard", "Premium".
    :type tier: str or ~azure.mgmt.mixedreality.models.SkuTier
    :param size: The SKU size. When the name field is the combination of tier and some other value,
     this would be the standalone code.
    :type size: str
    :param family: If the service has different generations of hardware, for the same SKU, then
     that can be captured here.
    :type family: str
    :param capacity: If the SKU supports scale out/in then the capacity integer should be included.
     If scale out/in is not possible for the resource this may be omitted.
    :type capacity: int
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'size': {'key': 'size', 'type': 'str'},
        'family': {'key': 'family', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Sku, self).__init__(**kwargs)
        self.name = kwargs['name']
        self.tier = kwargs.get('tier', None)
        self.size = kwargs.get('size', None)
        self.family = kwargs.get('family', None)
        self.capacity = kwargs.get('capacity', None)


class SpatialAnchorsAccount(TrackedResource):
    """SpatialAnchorsAccount Response.

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
    :param identity: The identity associated with this account.
    :type identity: ~azure.mgmt.mixedreality.models.Identity
    :param plan: The plan associated with this account.
    :type plan: ~azure.mgmt.mixedreality.models.Identity
    :param sku: The sku associated with this account.
    :type sku: ~azure.mgmt.mixedreality.models.Sku
    :param kind: The kind of account, if supported.
    :type kind: ~azure.mgmt.mixedreality.models.Sku
    :ivar system_data: System metadata for this account.
    :vartype system_data: ~azure.mgmt.mixedreality.models.SystemData
    :param storage_account_name: The name of the storage account associated with this accountId.
    :type storage_account_name: str
    :ivar account_id: unique id of certain account.
    :vartype account_id: str
    :ivar account_domain: Correspond domain name of certain Spatial Anchors Account.
    :vartype account_domain: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'system_data': {'readonly': True},
        'account_id': {'readonly': True},
        'account_domain': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'Identity'},
        'plan': {'key': 'plan', 'type': 'Identity'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'kind': {'key': 'kind', 'type': 'Sku'},
        'system_data': {'key': 'systemData', 'type': 'SystemData'},
        'storage_account_name': {'key': 'properties.storageAccountName', 'type': 'str'},
        'account_id': {'key': 'properties.accountId', 'type': 'str'},
        'account_domain': {'key': 'properties.accountDomain', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SpatialAnchorsAccount, self).__init__(**kwargs)
        self.identity = kwargs.get('identity', None)
        self.plan = kwargs.get('plan', None)
        self.sku = kwargs.get('sku', None)
        self.kind = kwargs.get('kind', None)
        self.system_data = None
        self.storage_account_name = kwargs.get('storage_account_name', None)
        self.account_id = None
        self.account_domain = None


class SpatialAnchorsAccountPage(msrest.serialization.Model):
    """Result of the request to get resource collection. It contains a list of resources and a URL link to get the next set of results.

    :param value: List of resources supported by the Resource Provider.
    :type value: list[~azure.mgmt.mixedreality.models.SpatialAnchorsAccount]
    :param next_link: URL to get the next set of resource list results if there are any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[SpatialAnchorsAccount]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SpatialAnchorsAccountPage, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)


class SystemData(msrest.serialization.Model):
    """Metadata pertaining to creation and last modification of the resource.

    :param created_by: The identity that created the resource.
    :type created_by: str
    :param created_by_type: The type of identity that created the resource. Possible values
     include: "User", "Application", "ManagedIdentity", "Key".
    :type created_by_type: str or ~azure.mgmt.mixedreality.models.CreatedByType
    :param created_at: The timestamp of resource creation (UTC).
    :type created_at: ~datetime.datetime
    :param last_modified_by: The identity that last modified the resource.
    :type last_modified_by: str
    :param last_modified_by_type: The type of identity that last modified the resource. Possible
     values include: "User", "Application", "ManagedIdentity", "Key".
    :type last_modified_by_type: str or ~azure.mgmt.mixedreality.models.CreatedByType
    :param last_modified_at: The timestamp of resource last modification (UTC).
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
