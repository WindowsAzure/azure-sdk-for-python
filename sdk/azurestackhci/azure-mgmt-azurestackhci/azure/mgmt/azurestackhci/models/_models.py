# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class AvailableOperations(msrest.serialization.Model):
    """Available operations of the service.

    :param value: Collection of available operation details.
    :type value: list[~azure_stack_hci_client.models.OperationDetail]
    :param next_link: URL client should use to fetch the next page (per server side paging).
     It's null for now, added for future use.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[OperationDetail]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AvailableOperations, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)


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


class Cluster(TrackedResource):
    """Cluster details.

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
    :ivar provisioning_state: Provisioning state. Possible values include: "Succeeded", "Failed",
     "Canceled", "Accepted", "Provisioning".
    :vartype provisioning_state: str or ~azure_stack_hci_client.models.ProvisioningState
    :ivar status: Status of the cluster agent. Possible values include: "NotYetRegistered",
     "ConnectedRecently", "NotConnectedRecently", "Disconnected", "Error".
    :vartype status: str or ~azure_stack_hci_client.models.Status
    :ivar cloud_id: Unique, immutable resource id.
    :vartype cloud_id: str
    :param aad_client_id: App id of cluster AAD identity.
    :type aad_client_id: str
    :param aad_tenant_id: Tenant id of cluster AAD identity.
    :type aad_tenant_id: str
    :param reported_properties: Properties reported by cluster agent.
    :type reported_properties: ~azure_stack_hci_client.models.ClusterReportedProperties
    :ivar trial_days_remaining: Number of days remaining in the trial period.
    :vartype trial_days_remaining: float
    :ivar billing_model: Type of billing applied to the resource.
    :vartype billing_model: str
    :ivar registration_timestamp: First cluster sync timestamp.
    :vartype registration_timestamp: ~datetime.datetime
    :ivar last_sync_timestamp: Most recent cluster sync timestamp.
    :vartype last_sync_timestamp: ~datetime.datetime
    :ivar last_billing_timestamp: Most recent billing meter timestamp.
    :vartype last_billing_timestamp: ~datetime.datetime
    :param created_by: The identity that created the resource.
    :type created_by: str
    :param created_by_type: The type of identity that created the resource. Possible values
     include: "User", "Application", "ManagedIdentity", "Key".
    :type created_by_type: str or ~azure_stack_hci_client.models.CreatedByType
    :param created_at: The timestamp of resource creation (UTC).
    :type created_at: ~datetime.datetime
    :param last_modified_by: The identity that last modified the resource.
    :type last_modified_by: str
    :param last_modified_by_type: The type of identity that last modified the resource. Possible
     values include: "User", "Application", "ManagedIdentity", "Key".
    :type last_modified_by_type: str or ~azure_stack_hci_client.models.CreatedByType
    :param last_modified_at: The timestamp of resource last modification (UTC).
    :type last_modified_at: ~datetime.datetime
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'status': {'readonly': True},
        'cloud_id': {'readonly': True},
        'trial_days_remaining': {'readonly': True},
        'billing_model': {'readonly': True},
        'registration_timestamp': {'readonly': True},
        'last_sync_timestamp': {'readonly': True},
        'last_billing_timestamp': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'cloud_id': {'key': 'properties.cloudId', 'type': 'str'},
        'aad_client_id': {'key': 'properties.aadClientId', 'type': 'str'},
        'aad_tenant_id': {'key': 'properties.aadTenantId', 'type': 'str'},
        'reported_properties': {'key': 'properties.reportedProperties', 'type': 'ClusterReportedProperties'},
        'trial_days_remaining': {'key': 'properties.trialDaysRemaining', 'type': 'float'},
        'billing_model': {'key': 'properties.billingModel', 'type': 'str'},
        'registration_timestamp': {'key': 'properties.registrationTimestamp', 'type': 'iso-8601'},
        'last_sync_timestamp': {'key': 'properties.lastSyncTimestamp', 'type': 'iso-8601'},
        'last_billing_timestamp': {'key': 'properties.lastBillingTimestamp', 'type': 'iso-8601'},
        'created_by': {'key': 'systemData.createdBy', 'type': 'str'},
        'created_by_type': {'key': 'systemData.createdByType', 'type': 'str'},
        'created_at': {'key': 'systemData.createdAt', 'type': 'iso-8601'},
        'last_modified_by': {'key': 'systemData.lastModifiedBy', 'type': 'str'},
        'last_modified_by_type': {'key': 'systemData.lastModifiedByType', 'type': 'str'},
        'last_modified_at': {'key': 'systemData.lastModifiedAt', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Cluster, self).__init__(**kwargs)
        self.provisioning_state = None
        self.status = None
        self.cloud_id = None
        self.aad_client_id = kwargs.get('aad_client_id', None)
        self.aad_tenant_id = kwargs.get('aad_tenant_id', None)
        self.reported_properties = kwargs.get('reported_properties', None)
        self.trial_days_remaining = None
        self.billing_model = None
        self.registration_timestamp = None
        self.last_sync_timestamp = None
        self.last_billing_timestamp = None
        self.created_by = kwargs.get('created_by', None)
        self.created_by_type = kwargs.get('created_by_type', None)
        self.created_at = kwargs.get('created_at', None)
        self.last_modified_by = kwargs.get('last_modified_by', None)
        self.last_modified_by_type = kwargs.get('last_modified_by_type', None)
        self.last_modified_at = kwargs.get('last_modified_at', None)


class ClusterList(msrest.serialization.Model):
    """List of clusters.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param value: List of clusters.
    :type value: list[~azure_stack_hci_client.models.Cluster]
    :ivar next_link: Link to the next set of results.
    :vartype next_link: str
    """

    _validation = {
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Cluster]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ClusterList, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = None


class ClusterNode(msrest.serialization.Model):
    """Cluster node details.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar name: Name of the cluster node.
    :vartype name: str
    :ivar id: Id of the node in the cluster.
    :vartype id: float
    :ivar manufacturer: Manufacturer of the cluster node hardware.
    :vartype manufacturer: str
    :ivar model: Model name of the cluster node hardware.
    :vartype model: str
    :ivar os_name: Operating system running on the cluster node.
    :vartype os_name: str
    :ivar os_version: Version of the operating system running on the cluster node.
    :vartype os_version: str
    :ivar serial_number: Immutable id of the cluster node.
    :vartype serial_number: str
    :ivar core_count: Number of physical cores on the cluster node.
    :vartype core_count: float
    :ivar memory_in_gi_b: Total available memory on the cluster node (in GiB).
    :vartype memory_in_gi_b: float
    """

    _validation = {
        'name': {'readonly': True},
        'id': {'readonly': True},
        'manufacturer': {'readonly': True},
        'model': {'readonly': True},
        'os_name': {'readonly': True},
        'os_version': {'readonly': True},
        'serial_number': {'readonly': True},
        'core_count': {'readonly': True},
        'memory_in_gi_b': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'float'},
        'manufacturer': {'key': 'manufacturer', 'type': 'str'},
        'model': {'key': 'model', 'type': 'str'},
        'os_name': {'key': 'osName', 'type': 'str'},
        'os_version': {'key': 'osVersion', 'type': 'str'},
        'serial_number': {'key': 'serialNumber', 'type': 'str'},
        'core_count': {'key': 'coreCount', 'type': 'float'},
        'memory_in_gi_b': {'key': 'memoryInGiB', 'type': 'float'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ClusterNode, self).__init__(**kwargs)
        self.name = None
        self.id = None
        self.manufacturer = None
        self.model = None
        self.os_name = None
        self.os_version = None
        self.serial_number = None
        self.core_count = None
        self.memory_in_gi_b = None


class ClusterReportedProperties(msrest.serialization.Model):
    """Properties reported by cluster agent.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar cluster_name: Name of the on-prem cluster connected to this resource.
    :vartype cluster_name: str
    :ivar cluster_id: Unique id generated by the on-prem cluster.
    :vartype cluster_id: str
    :ivar cluster_version: Version of the cluster software.
    :vartype cluster_version: str
    :ivar nodes: List of nodes reported by the cluster.
    :vartype nodes: list[~azure_stack_hci_client.models.ClusterNode]
    :ivar last_updated: Last time the cluster reported the data.
    :vartype last_updated: ~datetime.datetime
    """

    _validation = {
        'cluster_name': {'readonly': True},
        'cluster_id': {'readonly': True},
        'cluster_version': {'readonly': True},
        'nodes': {'readonly': True},
        'last_updated': {'readonly': True},
    }

    _attribute_map = {
        'cluster_name': {'key': 'clusterName', 'type': 'str'},
        'cluster_id': {'key': 'clusterId', 'type': 'str'},
        'cluster_version': {'key': 'clusterVersion', 'type': 'str'},
        'nodes': {'key': 'nodes', 'type': '[ClusterNode]'},
        'last_updated': {'key': 'lastUpdated', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ClusterReportedProperties, self).__init__(**kwargs)
        self.cluster_name = None
        self.cluster_id = None
        self.cluster_version = None
        self.nodes = None
        self.last_updated = None


class ClusterUpdate(msrest.serialization.Model):
    """Cluster details to update.

    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ClusterUpdate, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)


class ErrorAdditionalInfo(msrest.serialization.Model):
    """The resource management error additional info.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar type: The additional info type.
    :vartype type: str
    :ivar info: The additional info.
    :vartype info: any
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
    :vartype details: list[~azure_stack_hci_client.models.ErrorDetail]
    :ivar additional_info: The error additional info.
    :vartype additional_info: list[~azure_stack_hci_client.models.ErrorAdditionalInfo]
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
    :type error: ~azure_stack_hci_client.models.ErrorDetail
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorDetail'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = kwargs.get('error', None)


class OperationDetail(msrest.serialization.Model):
    """Operation detail payload.

    :param name: Name of the operation.
    :type name: str
    :param is_data_action: Indicates whether the operation is a data action.
    :type is_data_action: bool
    :param display: Display of the operation.
    :type display: ~azure_stack_hci_client.models.OperationDisplay
    :param origin: Origin of the operation.
    :type origin: str
    :param properties: Properties of the operation.
    :type properties: any
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'is_data_action': {'key': 'isDataAction', 'type': 'bool'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
        'origin': {'key': 'origin', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'object'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OperationDetail, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.is_data_action = kwargs.get('is_data_action', None)
        self.display = kwargs.get('display', None)
        self.origin = kwargs.get('origin', None)
        self.properties = kwargs.get('properties', None)


class OperationDisplay(msrest.serialization.Model):
    """Operation display payload.

    :param provider: Resource provider of the operation.
    :type provider: str
    :param resource: Resource of the operation.
    :type resource: str
    :param operation: Localized friendly name for the operation.
    :type operation: str
    :param description: Localized friendly description for the operation.
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
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = kwargs.get('provider', None)
        self.resource = kwargs.get('resource', None)
        self.operation = kwargs.get('operation', None)
        self.description = kwargs.get('description', None)
