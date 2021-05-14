# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import datetime
from typing import Dict, List, Optional, Union

from azure.core.exceptions import HttpResponseError
import msrest.serialization

from ._microsoft_elastic_enums import *


class CompanyInfo(msrest.serialization.Model):
    """Company information of the user to be passed to partners.

    :param domain: Domain of the company.
    :type domain: str
    :param business: Business of the company.
    :type business: str
    :param employees_number: Number of employees in the company.
    :type employees_number: str
    :param state: State of the company location.
    :type state: str
    :param country: Country of the company location.
    :type country: str
    """

    _validation = {
        'domain': {'max_length': 250, 'min_length': 0},
        'business': {'max_length': 50, 'min_length': 0},
        'employees_number': {'max_length': 20, 'min_length': 0},
        'state': {'max_length': 50, 'min_length': 0},
        'country': {'max_length': 50, 'min_length': 0},
    }

    _attribute_map = {
        'domain': {'key': 'domain', 'type': 'str'},
        'business': {'key': 'business', 'type': 'str'},
        'employees_number': {'key': 'employeesNumber', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'country': {'key': 'country', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        domain: Optional[str] = None,
        business: Optional[str] = None,
        employees_number: Optional[str] = None,
        state: Optional[str] = None,
        country: Optional[str] = None,
        **kwargs
    ):
        super(CompanyInfo, self).__init__(**kwargs)
        self.domain = domain
        self.business = business
        self.employees_number = employees_number
        self.state = state
        self.country = country


class DeploymentInfoResponse(msrest.serialization.Model):
    """The properties of deployment in Elastic cloud corresponding to the Elastic monitor resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar status: The Elastic deployment status. Possible values include: "Healthy", "Unhealthy".
    :vartype status: str or ~azure.mgmt.elastic.models.ElasticDeploymentStatus
    :ivar version: Version of the elasticsearch in Elastic cloud deployment.
    :vartype version: str
    :ivar memory_capacity: RAM capacity of the elasticsearch in Elastic cloud deployment.
    :vartype memory_capacity: str
    :ivar disk_capacity: Disk capacity of the elasticsearch in Elastic cloud deployment.
    :vartype disk_capacity: str
    """

    _validation = {
        'status': {'readonly': True},
        'version': {'readonly': True},
        'memory_capacity': {'readonly': True},
        'disk_capacity': {'readonly': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'memory_capacity': {'key': 'memoryCapacity', 'type': 'str'},
        'disk_capacity': {'key': 'diskCapacity', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DeploymentInfoResponse, self).__init__(**kwargs)
        self.status = None
        self.version = None
        self.memory_capacity = None
        self.disk_capacity = None


class ElasticCloudDeployment(msrest.serialization.Model):
    """Details of the user's elastic deployment associated with the monitor resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar name: Elastic deployment name.
    :vartype name: str
    :ivar deployment_id: Elastic deployment Id.
    :vartype deployment_id: str
    :ivar azure_subscription_id: Associated Azure subscription Id for the elastic deployment.
    :vartype azure_subscription_id: str
    :ivar elasticsearch_region: Region where Deployment at Elastic side took place.
    :vartype elasticsearch_region: str
    :ivar elasticsearch_service_url: Elasticsearch ingestion endpoint of the Elastic deployment.
    :vartype elasticsearch_service_url: str
    :ivar kibana_service_url: Kibana endpoint of the Elastic deployment.
    :vartype kibana_service_url: str
    :ivar kibana_sso_url: Kibana dashboard sso URL of the Elastic deployment.
    :vartype kibana_sso_url: str
    """

    _validation = {
        'name': {'readonly': True},
        'deployment_id': {'readonly': True},
        'azure_subscription_id': {'readonly': True},
        'elasticsearch_region': {'readonly': True},
        'elasticsearch_service_url': {'readonly': True},
        'kibana_service_url': {'readonly': True},
        'kibana_sso_url': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'deployment_id': {'key': 'deploymentId', 'type': 'str'},
        'azure_subscription_id': {'key': 'azureSubscriptionId', 'type': 'str'},
        'elasticsearch_region': {'key': 'elasticsearchRegion', 'type': 'str'},
        'elasticsearch_service_url': {'key': 'elasticsearchServiceUrl', 'type': 'str'},
        'kibana_service_url': {'key': 'kibanaServiceUrl', 'type': 'str'},
        'kibana_sso_url': {'key': 'kibanaSsoUrl', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ElasticCloudDeployment, self).__init__(**kwargs)
        self.name = None
        self.deployment_id = None
        self.azure_subscription_id = None
        self.elasticsearch_region = None
        self.elasticsearch_service_url = None
        self.kibana_service_url = None
        self.kibana_sso_url = None


class ElasticCloudUser(msrest.serialization.Model):
    """Details of the user's elastic account.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar email_address: Email of the Elastic User Account.
    :vartype email_address: str
    :ivar id: User Id of the elastic account of the User.
    :vartype id: str
    :ivar elastic_cloud_sso_default_url: Elastic cloud default dashboard sso URL of the Elastic
     user account.
    :vartype elastic_cloud_sso_default_url: str
    """

    _validation = {
        'email_address': {'readonly': True},
        'id': {'readonly': True},
        'elastic_cloud_sso_default_url': {'readonly': True},
    }

    _attribute_map = {
        'email_address': {'key': 'emailAddress', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'elastic_cloud_sso_default_url': {'key': 'elasticCloudSsoDefaultUrl', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ElasticCloudUser, self).__init__(**kwargs)
        self.email_address = None
        self.id = None
        self.elastic_cloud_sso_default_url = None


class ElasticMonitorResource(msrest.serialization.Model):
    """Monitor resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: ARM id of the monitor resource.
    :vartype id: str
    :ivar name: Name of the monitor resource.
    :vartype name: str
    :ivar type: The type of the monitor resource.
    :vartype type: str
    :param sku: SKU of the monitor resource.
    :type sku: ~azure.mgmt.elastic.models.ResourceSku
    :param properties: Properties of the monitor resource.
    :type properties: ~azure.mgmt.elastic.models.MonitorProperties
    :param identity: Identity properties of the monitor resource.
    :type identity: ~azure.mgmt.elastic.models.IdentityProperties
    :param tags: A set of tags. The tags of the monitor resource.
    :type tags: dict[str, str]
    :param location: Required. The location of the monitor resource.
    :type location: str
    :ivar system_data: The system metadata relating to this resource.
    :vartype system_data: ~azure.mgmt.elastic.models.SystemData
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'system_data': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'ResourceSku'},
        'properties': {'key': 'properties', 'type': 'MonitorProperties'},
        'identity': {'key': 'identity', 'type': 'IdentityProperties'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'system_data': {'key': 'systemData', 'type': 'SystemData'},
    }

    def __init__(
        self,
        *,
        location: str,
        sku: Optional["ResourceSku"] = None,
        properties: Optional["MonitorProperties"] = None,
        identity: Optional["IdentityProperties"] = None,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(ElasticMonitorResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.sku = sku
        self.properties = properties
        self.identity = identity
        self.tags = tags
        self.location = location
        self.system_data = None


class ElasticMonitorResourceListResponse(msrest.serialization.Model):
    """Response of a list operation.

    :param value: Results of a list operation.
    :type value: list[~azure.mgmt.elastic.models.ElasticMonitorResource]
    :param next_link: Link to the next set of results, if any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ElasticMonitorResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["ElasticMonitorResource"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(ElasticMonitorResourceListResponse, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class ElasticMonitorResourceUpdateParameters(msrest.serialization.Model):
    """Monitor resource update parameters.

    :param tags: A set of tags. elastic monitor resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        *,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(ElasticMonitorResourceUpdateParameters, self).__init__(**kwargs)
        self.tags = tags


class ElasticProperties(msrest.serialization.Model):
    """Elastic Resource Properties.

    :param elastic_cloud_user: Details of the user's elastic account.
    :type elastic_cloud_user: ~azure.mgmt.elastic.models.ElasticCloudUser
    :param elastic_cloud_deployment: Details of the elastic cloud deployment.
    :type elastic_cloud_deployment: ~azure.mgmt.elastic.models.ElasticCloudDeployment
    """

    _attribute_map = {
        'elastic_cloud_user': {'key': 'elasticCloudUser', 'type': 'ElasticCloudUser'},
        'elastic_cloud_deployment': {'key': 'elasticCloudDeployment', 'type': 'ElasticCloudDeployment'},
    }

    def __init__(
        self,
        *,
        elastic_cloud_user: Optional["ElasticCloudUser"] = None,
        elastic_cloud_deployment: Optional["ElasticCloudDeployment"] = None,
        **kwargs
    ):
        super(ElasticProperties, self).__init__(**kwargs)
        self.elastic_cloud_user = elastic_cloud_user
        self.elastic_cloud_deployment = elastic_cloud_deployment


class ErrorResponseBody(msrest.serialization.Model):
    """Error response body.

    :param code: Error code.
    :type code: str
    :param message: Error message.
    :type message: str
    :param target: Error target.
    :type target: str
    :param details: Error details.
    :type details: list[~azure.mgmt.elastic.models.ErrorResponseBody]
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorResponseBody]'},
    }

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        message: Optional[str] = None,
        target: Optional[str] = None,
        details: Optional[List["ErrorResponseBody"]] = None,
        **kwargs
    ):
        super(ErrorResponseBody, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.target = target
        self.details = details


class FilteringTag(msrest.serialization.Model):
    """The definition of a filtering tag. Filtering tags are used for capturing resources and include/exclude them from being monitored.

    :param name: The name (also known as the key) of the tag.
    :type name: str
    :param value: The value of the tag.
    :type value: str
    :param action: Valid actions for a filtering tag. Possible values include: "Include",
     "Exclude".
    :type action: str or ~azure.mgmt.elastic.models.TagAction
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
        'action': {'key': 'action', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        value: Optional[str] = None,
        action: Optional[Union[str, "TagAction"]] = None,
        **kwargs
    ):
        super(FilteringTag, self).__init__(**kwargs)
        self.name = name
        self.value = value
        self.action = action


class IdentityProperties(msrest.serialization.Model):
    """Identity properties.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar principal_id: The identity ID.
    :vartype principal_id: str
    :ivar tenant_id: The tenant ID of resource.
    :vartype tenant_id: str
    :param type: Managed identity type. Possible values include: "SystemAssigned".
    :type type: str or ~azure.mgmt.elastic.models.ManagedIdentityTypes
    """

    _validation = {
        'principal_id': {'readonly': True},
        'tenant_id': {'readonly': True},
    }

    _attribute_map = {
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        type: Optional[Union[str, "ManagedIdentityTypes"]] = None,
        **kwargs
    ):
        super(IdentityProperties, self).__init__(**kwargs)
        self.principal_id = None
        self.tenant_id = None
        self.type = type


class LogRules(msrest.serialization.Model):
    """Set of rules for sending logs for the Monitor resource.

    :param send_aad_logs: Flag specifying if AAD logs should be sent for the Monitor resource.
    :type send_aad_logs: bool
    :param send_subscription_logs: Flag specifying if subscription logs should be sent for the
     Monitor resource.
    :type send_subscription_logs: bool
    :param send_activity_logs: Flag specifying if activity logs from Azure resources should be sent
     for the Monitor resource.
    :type send_activity_logs: bool
    :param filtering_tags: List of filtering tags to be used for capturing logs. This only takes
     effect if SendActivityLogs flag is enabled. If empty, all resources will be captured. If only
     Exclude action is specified, the rules will apply to the list of all available resources. If
     Include actions are specified, the rules will only include resources with the associated tags.
    :type filtering_tags: list[~azure.mgmt.elastic.models.FilteringTag]
    """

    _attribute_map = {
        'send_aad_logs': {'key': 'sendAadLogs', 'type': 'bool'},
        'send_subscription_logs': {'key': 'sendSubscriptionLogs', 'type': 'bool'},
        'send_activity_logs': {'key': 'sendActivityLogs', 'type': 'bool'},
        'filtering_tags': {'key': 'filteringTags', 'type': '[FilteringTag]'},
    }

    def __init__(
        self,
        *,
        send_aad_logs: Optional[bool] = None,
        send_subscription_logs: Optional[bool] = None,
        send_activity_logs: Optional[bool] = None,
        filtering_tags: Optional[List["FilteringTag"]] = None,
        **kwargs
    ):
        super(LogRules, self).__init__(**kwargs)
        self.send_aad_logs = send_aad_logs
        self.send_subscription_logs = send_subscription_logs
        self.send_activity_logs = send_activity_logs
        self.filtering_tags = filtering_tags


class MonitoredResource(msrest.serialization.Model):
    """The properties of a resource currently being monitored by the Elastic monitor resource.

    :param id: The ARM id of the resource.
    :type id: str
    :param sending_logs: Flag indicating the status of the resource for sending logs operation to
     Elastic. Possible values include: "True", "False".
    :type sending_logs: str or ~azure.mgmt.elastic.models.SendingLogs
    :param reason_for_logs_status: Reason for why the resource is sending logs (or why it is not
     sending).
    :type reason_for_logs_status: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'sending_logs': {'key': 'sendingLogs', 'type': 'str'},
        'reason_for_logs_status': {'key': 'reasonForLogsStatus', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        sending_logs: Optional[Union[str, "SendingLogs"]] = None,
        reason_for_logs_status: Optional[str] = None,
        **kwargs
    ):
        super(MonitoredResource, self).__init__(**kwargs)
        self.id = id
        self.sending_logs = sending_logs
        self.reason_for_logs_status = reason_for_logs_status


class MonitoredResourceListResponse(msrest.serialization.Model):
    """Response of a list operation.

    :param value: Results of a list operation.
    :type value: list[~azure.mgmt.elastic.models.MonitoredResource]
    :param next_link: Link to the next set of results, if any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[MonitoredResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["MonitoredResource"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(MonitoredResourceListResponse, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class MonitoringTagRules(msrest.serialization.Model):
    """Capture logs and metrics of Azure resources based on ARM tags.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar name: Name of the rule set.
    :vartype name: str
    :ivar id: The id of the rule set.
    :vartype id: str
    :ivar type: The type of the rule set.
    :vartype type: str
    :param properties: Properties of the monitoring tag rules.
    :type properties: ~azure.mgmt.elastic.models.MonitoringTagRulesProperties
    :ivar system_data: The system metadata relating to this resource.
    :vartype system_data: ~azure.mgmt.elastic.models.SystemData
    """

    _validation = {
        'name': {'readonly': True},
        'id': {'readonly': True},
        'type': {'readonly': True},
        'system_data': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'MonitoringTagRulesProperties'},
        'system_data': {'key': 'systemData', 'type': 'SystemData'},
    }

    def __init__(
        self,
        *,
        properties: Optional["MonitoringTagRulesProperties"] = None,
        **kwargs
    ):
        super(MonitoringTagRules, self).__init__(**kwargs)
        self.name = None
        self.id = None
        self.type = None
        self.properties = properties
        self.system_data = None


class MonitoringTagRulesListResponse(msrest.serialization.Model):
    """Response of a list operation.

    :param value: Results of a list operation.
    :type value: list[~azure.mgmt.elastic.models.MonitoringTagRules]
    :param next_link: Link to the next set of results, if any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[MonitoringTagRules]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["MonitoringTagRules"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(MonitoringTagRulesListResponse, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class MonitoringTagRulesProperties(msrest.serialization.Model):
    """Definition of the properties for a TagRules resource.

    :param provisioning_state: Provisioning state of the monitoring tag rules. Possible values
     include: "Accepted", "Creating", "Updating", "Deleting", "Succeeded", "Failed", "Canceled",
     "Deleted", "NotSpecified".
    :type provisioning_state: str or ~azure.mgmt.elastic.models.ProvisioningState
    :param log_rules: Rules for sending logs.
    :type log_rules: ~azure.mgmt.elastic.models.LogRules
    """

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'log_rules': {'key': 'logRules', 'type': 'LogRules'},
    }

    def __init__(
        self,
        *,
        provisioning_state: Optional[Union[str, "ProvisioningState"]] = None,
        log_rules: Optional["LogRules"] = None,
        **kwargs
    ):
        super(MonitoringTagRulesProperties, self).__init__(**kwargs)
        self.provisioning_state = provisioning_state
        self.log_rules = log_rules


class MonitorProperties(msrest.serialization.Model):
    """Properties specific to the monitor resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param provisioning_state: Provisioning state of the monitor resource. Possible values include:
     "Accepted", "Creating", "Updating", "Deleting", "Succeeded", "Failed", "Canceled", "Deleted",
     "NotSpecified".
    :type provisioning_state: str or ~azure.mgmt.elastic.models.ProvisioningState
    :param monitoring_status: Flag specifying if the resource monitoring is enabled or disabled.
     Possible values include: "Enabled", "Disabled".
    :type monitoring_status: str or ~azure.mgmt.elastic.models.MonitoringStatus
    :param elastic_properties: Elastic cloud properties.
    :type elastic_properties: ~azure.mgmt.elastic.models.ElasticProperties
    :param user_info: User information.
    :type user_info: ~azure.mgmt.elastic.models.UserInfo
    :ivar liftr_resource_category:  Possible values include: "Unknown", "MonitorLogs".
    :vartype liftr_resource_category: str or ~azure.mgmt.elastic.models.LiftrResourceCategories
    :ivar liftr_resource_preference: The priority of the resource.
    :vartype liftr_resource_preference: int
    """

    _validation = {
        'liftr_resource_category': {'readonly': True},
        'liftr_resource_preference': {'readonly': True},
    }

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'monitoring_status': {'key': 'monitoringStatus', 'type': 'str'},
        'elastic_properties': {'key': 'elasticProperties', 'type': 'ElasticProperties'},
        'user_info': {'key': 'userInfo', 'type': 'UserInfo'},
        'liftr_resource_category': {'key': 'liftrResourceCategory', 'type': 'str'},
        'liftr_resource_preference': {'key': 'liftrResourcePreference', 'type': 'int'},
    }

    def __init__(
        self,
        *,
        provisioning_state: Optional[Union[str, "ProvisioningState"]] = None,
        monitoring_status: Optional[Union[str, "MonitoringStatus"]] = None,
        elastic_properties: Optional["ElasticProperties"] = None,
        user_info: Optional["UserInfo"] = None,
        **kwargs
    ):
        super(MonitorProperties, self).__init__(**kwargs)
        self.provisioning_state = provisioning_state
        self.monitoring_status = monitoring_status
        self.elastic_properties = elastic_properties
        self.user_info = user_info
        self.liftr_resource_category = None
        self.liftr_resource_preference = None


class OperationDisplay(msrest.serialization.Model):
    """The object that represents the operation.

    :param provider: Service provider, i.e., Microsoft.Elastic.
    :type provider: str
    :param resource: Type on which the operation is performed, e.g., 'monitors'.
    :type resource: str
    :param operation: Operation type, e.g., read, write, delete, etc.
    :type operation: str
    :param description: Description of the operation, e.g., 'Write monitors'.
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


class OperationListResult(msrest.serialization.Model):
    """Result of GET request to list the Microsoft.Elastic operations.

    :param value: List of operations supported by the Microsoft.Elastic provider.
    :type value: list[~azure.mgmt.elastic.models.OperationResult]
    :param next_link: URL to get the next set of operation list results if there are any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[OperationResult]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["OperationResult"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(OperationListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class OperationResult(msrest.serialization.Model):
    """A Microsoft.Elastic REST API operation.

    :param name: Operation name, i.e., {provider}/{resource}/{operation}.
    :type name: str
    :param is_data_action: Indicates whether the operation is a data action.
    :type is_data_action: bool
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.elastic.models.OperationDisplay
    :param origin: Origin of the operation.
    :type origin: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'is_data_action': {'key': 'isDataAction', 'type': 'bool'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
        'origin': {'key': 'origin', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        is_data_action: Optional[bool] = None,
        display: Optional["OperationDisplay"] = None,
        origin: Optional[str] = None,
        **kwargs
    ):
        super(OperationResult, self).__init__(**kwargs)
        self.name = name
        self.is_data_action = is_data_action
        self.display = display
        self.origin = origin


class ResourceProviderDefaultErrorResponse(msrest.serialization.Model):
    """RP default error response.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar error: Response body of Error.
    :vartype error: ~azure.mgmt.elastic.models.ErrorResponseBody
    """

    _validation = {
        'error': {'readonly': True},
    }

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorResponseBody'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ResourceProviderDefaultErrorResponse, self).__init__(**kwargs)
        self.error = None


class ResourceSku(msrest.serialization.Model):
    """Microsoft.Elastic SKU.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Name of the SKU.
    :type name: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name: str,
        **kwargs
    ):
        super(ResourceSku, self).__init__(**kwargs)
        self.name = name


class SystemData(msrest.serialization.Model):
    """Metadata pertaining to creation and last modification of the resource.

    :param created_by: The identity that created the resource.
    :type created_by: str
    :param created_by_type: The type of identity that created the resource. Possible values
     include: "User", "Application", "ManagedIdentity", "Key".
    :type created_by_type: str or ~azure.mgmt.elastic.models.CreatedByType
    :param created_at: The timestamp of resource creation (UTC).
    :type created_at: ~datetime.datetime
    :param last_modified_by: The identity that last modified the resource.
    :type last_modified_by: str
    :param last_modified_by_type: The type of identity that last modified the resource. Possible
     values include: "User", "Application", "ManagedIdentity", "Key".
    :type last_modified_by_type: str or ~azure.mgmt.elastic.models.CreatedByType
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
        *,
        created_by: Optional[str] = None,
        created_by_type: Optional[Union[str, "CreatedByType"]] = None,
        created_at: Optional[datetime.datetime] = None,
        last_modified_by: Optional[str] = None,
        last_modified_by_type: Optional[Union[str, "CreatedByType"]] = None,
        last_modified_at: Optional[datetime.datetime] = None,
        **kwargs
    ):
        super(SystemData, self).__init__(**kwargs)
        self.created_by = created_by
        self.created_by_type = created_by_type
        self.created_at = created_at
        self.last_modified_by = last_modified_by
        self.last_modified_by_type = last_modified_by_type
        self.last_modified_at = last_modified_at


class UserInfo(msrest.serialization.Model):
    """User Information to be passed to partners.

    :param first_name: First name of the user.
    :type first_name: str
    :param last_name: Last name of the user.
    :type last_name: str
    :param company_name: Company name of the user.
    :type company_name: str
    :param email_address: Email of the user used by Elastic for contacting them if needed.
    :type email_address: str
    :param company_info: Company information of the user to be passed to partners.
    :type company_info: ~azure.mgmt.elastic.models.CompanyInfo
    """

    _validation = {
        'first_name': {'max_length': 50, 'min_length': 0},
        'last_name': {'max_length': 50, 'min_length': 0},
        'company_name': {'max_length': 50, 'min_length': 0},
        'email_address': {'pattern': r'^([^<>()\[\]\.,;:\s@"]+(\.[^<>()\[\]\.,;:\s@"]+)*)@(([a-zA-Z-_0-9]+\.)+[a-zA-Z]{2,})$'},
    }

    _attribute_map = {
        'first_name': {'key': 'firstName', 'type': 'str'},
        'last_name': {'key': 'lastName', 'type': 'str'},
        'company_name': {'key': 'companyName', 'type': 'str'},
        'email_address': {'key': 'emailAddress', 'type': 'str'},
        'company_info': {'key': 'companyInfo', 'type': 'CompanyInfo'},
    }

    def __init__(
        self,
        *,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        company_name: Optional[str] = None,
        email_address: Optional[str] = None,
        company_info: Optional["CompanyInfo"] = None,
        **kwargs
    ):
        super(UserInfo, self).__init__(**kwargs)
        self.first_name = first_name
        self.last_name = last_name
        self.company_name = company_name
        self.email_address = email_address
        self.company_info = company_info


class VMCollectionUpdate(msrest.serialization.Model):
    """Update VM resource collection.

    :param vm_resource_id: ARM id of the VM resource.
    :type vm_resource_id: str
    :param operation_name: Operation to be performed for given VM. Possible values include: "Add",
     "Delete".
    :type operation_name: str or ~azure.mgmt.elastic.models.OperationName
    """

    _attribute_map = {
        'vm_resource_id': {'key': 'vmResourceId', 'type': 'str'},
        'operation_name': {'key': 'operationName', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        vm_resource_id: Optional[str] = None,
        operation_name: Optional[Union[str, "OperationName"]] = None,
        **kwargs
    ):
        super(VMCollectionUpdate, self).__init__(**kwargs)
        self.vm_resource_id = vm_resource_id
        self.operation_name = operation_name


class VMHostListResponse(msrest.serialization.Model):
    """Response of a list operation.

    :param value: Results of a list operation.
    :type value: list[~azure.mgmt.elastic.models.VMResources]
    :param next_link: Link to the next Vm resource Id, if any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[VMResources]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["VMResources"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(VMHostListResponse, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class VMIngestionDetailsResponse(msrest.serialization.Model):
    """The vm ingestion details to install an agent.

    :param cloud_id: The cloudId of given Elastic monitor resource.
    :type cloud_id: str
    :param ingestion_key: Ingestion details to install agent on given VM.
    :type ingestion_key: str
    """

    _attribute_map = {
        'cloud_id': {'key': 'cloudId', 'type': 'str'},
        'ingestion_key': {'key': 'ingestionKey', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        cloud_id: Optional[str] = None,
        ingestion_key: Optional[str] = None,
        **kwargs
    ):
        super(VMIngestionDetailsResponse, self).__init__(**kwargs)
        self.cloud_id = cloud_id
        self.ingestion_key = ingestion_key


class VMResources(msrest.serialization.Model):
    """The vm resource properties that is currently being monitored by the Elastic monitor resource.

    :param vm_resource_id: The ARM id of the VM resource.
    :type vm_resource_id: str
    """

    _attribute_map = {
        'vm_resource_id': {'key': 'vmResourceId', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        vm_resource_id: Optional[str] = None,
        **kwargs
    ):
        super(VMResources, self).__init__(**kwargs)
        self.vm_resource_id = vm_resource_id
