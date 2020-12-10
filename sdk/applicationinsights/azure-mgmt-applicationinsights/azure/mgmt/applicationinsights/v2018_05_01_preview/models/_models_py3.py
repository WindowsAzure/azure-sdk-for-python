# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Dict, List, Optional, Union

import msrest.serialization

from ._application_insights_management_client_enums import *


class ComponentsResource(msrest.serialization.Model):
    """An azure resource object.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :param location: Required. Resource location.
    :type location: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
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
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        *,
        location: str,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(ComponentsResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = location
        self.tags = tags


class ApplicationInsightsComponent(ComponentsResource):
    """An Application Insights component definition.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :param location: Required. Resource location.
    :type location: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param kind: Required. The kind of application that this component refers to, used to customize
     UI. This value is a freeform string, values should typically be one of the following: web, ios,
     other, store, java, phone.
    :type kind: str
    :ivar application_id: The unique ID of your application. This field mirrors the 'Name' field
     and cannot be changed.
    :vartype application_id: str
    :ivar app_id: Application Insights Unique ID for your Application.
    :vartype app_id: str
    :param application_type: Type of application being monitored. Possible values include: "web",
     "other". Default value: "web".
    :type application_type: str or
     ~azure.mgmt.applicationinsights.v2018_05_01_preview.models.ApplicationType
    :param flow_type: Used by the Application Insights system to determine what kind of flow this
     component was created by. This is to be set to 'Bluefield' when creating/updating a component
     via the REST API. Possible values include: "Bluefield". Default value: "Bluefield".
    :type flow_type: str or ~azure.mgmt.applicationinsights.v2018_05_01_preview.models.FlowType
    :param request_source: Describes what tool created this Application Insights component.
     Customers using this API should set this to the default 'rest'. Possible values include:
     "rest". Default value: "rest".
    :type request_source: str or
     ~azure.mgmt.applicationinsights.v2018_05_01_preview.models.RequestSource
    :ivar instrumentation_key: Application Insights Instrumentation key. A read-only value that
     applications can use to identify the destination for all telemetry sent to Azure Application
     Insights. This value will be supplied upon construction of each new Application Insights
     component.
    :vartype instrumentation_key: str
    :ivar creation_date: Creation Date for the Application Insights component, in ISO 8601 format.
    :vartype creation_date: ~datetime.datetime
    :ivar tenant_id: Azure Tenant Id.
    :vartype tenant_id: str
    :param hockey_app_id: The unique application ID created when a new application is added to
     HockeyApp, used for communications with HockeyApp.
    :type hockey_app_id: str
    :ivar hockey_app_token: Token used to authenticate communications with between Application
     Insights and HockeyApp.
    :vartype hockey_app_token: str
    :ivar provisioning_state: Current state of this component: whether or not is has been
     provisioned within the resource group it is defined. Users cannot change this value but are
     able to read from it. Values will include Succeeded, Deploying, Canceled, and Failed.
    :vartype provisioning_state: str
    :param sampling_percentage: Percentage of the data produced by the application being monitored
     that is being sampled for Application Insights telemetry.
    :type sampling_percentage: float
    :ivar connection_string: Application Insights component connection string.
    :vartype connection_string: str
    :param retention_in_days: Retention period in days.
    :type retention_in_days: int
    :param disable_ip_masking: Disable IP masking.
    :type disable_ip_masking: bool
    :param immediate_purge_data_on30_days: Purge data immediately after 30 days.
    :type immediate_purge_data_on30_days: bool
    :ivar private_link_scoped_resources: List of linked private link scope resources.
    :vartype private_link_scoped_resources:
     list[~azure.mgmt.applicationinsights.v2018_05_01_preview.models.PrivateLinkScopedResource]
    :param public_network_access_for_ingestion: The network access type for accessing Application
     Insights ingestion. Possible values include: "Enabled", "Disabled". Default value: "Enabled".
    :type public_network_access_for_ingestion: str or
     ~azure.mgmt.applicationinsights.v2018_05_01_preview.models.PublicNetworkAccessType
    :param public_network_access_for_query: The network access type for accessing Application
     Insights query. Possible values include: "Enabled", "Disabled". Default value: "Enabled".
    :type public_network_access_for_query: str or
     ~azure.mgmt.applicationinsights.v2018_05_01_preview.models.PublicNetworkAccessType
    :param ingestion_mode: Indicates the flow of the ingestion. Possible values include:
     "ApplicationInsights", "ApplicationInsightsWithDiagnosticSettings", "LogAnalytics". Default
     value: "ApplicationInsights".
    :type ingestion_mode: str or
     ~azure.mgmt.applicationinsights.v2018_05_01_preview.models.IngestionMode
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'kind': {'required': True},
        'application_id': {'readonly': True},
        'app_id': {'readonly': True},
        'instrumentation_key': {'readonly': True},
        'creation_date': {'readonly': True},
        'tenant_id': {'readonly': True},
        'hockey_app_token': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'connection_string': {'readonly': True},
        'private_link_scoped_resources': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'kind': {'key': 'kind', 'type': 'str'},
        'application_id': {'key': 'properties.ApplicationId', 'type': 'str'},
        'app_id': {'key': 'properties.AppId', 'type': 'str'},
        'application_type': {'key': 'properties.Application_Type', 'type': 'str'},
        'flow_type': {'key': 'properties.Flow_Type', 'type': 'str'},
        'request_source': {'key': 'properties.Request_Source', 'type': 'str'},
        'instrumentation_key': {'key': 'properties.InstrumentationKey', 'type': 'str'},
        'creation_date': {'key': 'properties.CreationDate', 'type': 'iso-8601'},
        'tenant_id': {'key': 'properties.TenantId', 'type': 'str'},
        'hockey_app_id': {'key': 'properties.HockeyAppId', 'type': 'str'},
        'hockey_app_token': {'key': 'properties.HockeyAppToken', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'sampling_percentage': {'key': 'properties.SamplingPercentage', 'type': 'float'},
        'connection_string': {'key': 'properties.ConnectionString', 'type': 'str'},
        'retention_in_days': {'key': 'properties.RetentionInDays', 'type': 'int'},
        'disable_ip_masking': {'key': 'properties.DisableIpMasking', 'type': 'bool'},
        'immediate_purge_data_on30_days': {'key': 'properties.ImmediatePurgeDataOn30Days', 'type': 'bool'},
        'private_link_scoped_resources': {'key': 'properties.PrivateLinkScopedResources', 'type': '[PrivateLinkScopedResource]'},
        'public_network_access_for_ingestion': {'key': 'properties.publicNetworkAccessForIngestion', 'type': 'str'},
        'public_network_access_for_query': {'key': 'properties.publicNetworkAccessForQuery', 'type': 'str'},
        'ingestion_mode': {'key': 'properties.IngestionMode', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        location: str,
        kind: str,
        tags: Optional[Dict[str, str]] = None,
        application_type: Optional[Union[str, "ApplicationType"]] = "web",
        flow_type: Optional[Union[str, "FlowType"]] = "Bluefield",
        request_source: Optional[Union[str, "RequestSource"]] = "rest",
        hockey_app_id: Optional[str] = None,
        sampling_percentage: Optional[float] = None,
        retention_in_days: Optional[int] = 90,
        disable_ip_masking: Optional[bool] = None,
        immediate_purge_data_on30_days: Optional[bool] = None,
        public_network_access_for_ingestion: Optional[Union[str, "PublicNetworkAccessType"]] = "Enabled",
        public_network_access_for_query: Optional[Union[str, "PublicNetworkAccessType"]] = "Enabled",
        ingestion_mode: Optional[Union[str, "IngestionMode"]] = "ApplicationInsights",
        **kwargs
    ):
        super(ApplicationInsightsComponent, self).__init__(location=location, tags=tags, **kwargs)
        self.kind = kind
        self.application_id = None
        self.app_id = None
        self.application_type = application_type
        self.flow_type = flow_type
        self.request_source = request_source
        self.instrumentation_key = None
        self.creation_date = None
        self.tenant_id = None
        self.hockey_app_id = hockey_app_id
        self.hockey_app_token = None
        self.provisioning_state = None
        self.sampling_percentage = sampling_percentage
        self.connection_string = None
        self.retention_in_days = retention_in_days
        self.disable_ip_masking = disable_ip_masking
        self.immediate_purge_data_on30_days = immediate_purge_data_on30_days
        self.private_link_scoped_resources = None
        self.public_network_access_for_ingestion = public_network_access_for_ingestion
        self.public_network_access_for_query = public_network_access_for_query
        self.ingestion_mode = ingestion_mode


class ApplicationInsightsComponentListResult(msrest.serialization.Model):
    """Describes the list of Application Insights Resources.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. List of Application Insights component definitions.
    :type value:
     list[~azure.mgmt.applicationinsights.v2018_05_01_preview.models.ApplicationInsightsComponent]
    :param next_link: The URI to get the next set of Application Insights component definitions if
     too many components where returned in the result set.
    :type next_link: str
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ApplicationInsightsComponent]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: List["ApplicationInsightsComponent"],
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(ApplicationInsightsComponentListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class ApplicationInsightsComponentProactiveDetectionConfiguration(msrest.serialization.Model):
    """A ProactiveDetection configuration definition.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Azure resource Id.
    :vartype id: str
    :param name: Azure resource name.
    :type name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :ivar name_properties_name: The rule name.
    :vartype name_properties_name: str
    :param enabled: A flag that indicates whether this rule is enabled by the user.
    :type enabled: bool
    :param send_emails_to_subscription_owners: A flag that indicated whether notifications on this
     rule should be sent to subscription owners.
    :type send_emails_to_subscription_owners: bool
    :param custom_emails: Custom email addresses for this rule notifications.
    :type custom_emails: list[str]
    :ivar last_updated_time: The last time this rule was updated.
    :vartype last_updated_time: str
    :param rule_definitions: Static definitions of the ProactiveDetection configuration rule (same
     values for all components).
    :type rule_definitions:
     ~azure.mgmt.applicationinsights.v2018_05_01_preview.models.ApplicationInsightsComponentProactiveDetectionConfigurationPropertiesRuleDefinitions
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name_properties_name': {'readonly': True},
        'last_updated_time': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'name_properties_name': {'key': 'properties.Name', 'type': 'str'},
        'enabled': {'key': 'properties.Enabled', 'type': 'bool'},
        'send_emails_to_subscription_owners': {'key': 'properties.SendEmailsToSubscriptionOwners', 'type': 'bool'},
        'custom_emails': {'key': 'properties.CustomEmails', 'type': '[str]'},
        'last_updated_time': {'key': 'properties.LastUpdatedTime', 'type': 'str'},
        'rule_definitions': {'key': 'properties.RuleDefinitions', 'type': 'ApplicationInsightsComponentProactiveDetectionConfigurationPropertiesRuleDefinitions'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        location: Optional[str] = None,
        enabled: Optional[bool] = None,
        send_emails_to_subscription_owners: Optional[bool] = None,
        custom_emails: Optional[List[str]] = None,
        rule_definitions: Optional["ApplicationInsightsComponentProactiveDetectionConfigurationPropertiesRuleDefinitions"] = None,
        **kwargs
    ):
        super(ApplicationInsightsComponentProactiveDetectionConfiguration, self).__init__(**kwargs)
        self.id = None
        self.name = name
        self.type = None
        self.location = location
        self.name_properties_name = None
        self.enabled = enabled
        self.send_emails_to_subscription_owners = send_emails_to_subscription_owners
        self.custom_emails = custom_emails
        self.last_updated_time = None
        self.rule_definitions = rule_definitions


class ApplicationInsightsComponentProactiveDetectionConfigurationPropertiesRuleDefinitions(msrest.serialization.Model):
    """Static definitions of the ProactiveDetection configuration rule (same values for all components).

    :param name: The rule name.
    :type name: str
    :param display_name: The rule name as it is displayed in UI.
    :type display_name: str
    :param description: The rule description.
    :type description: str
    :param help_url: URL which displays additional info about the proactive detection rule.
    :type help_url: str
    :param is_hidden: A flag indicating whether the rule is hidden (from the UI).
    :type is_hidden: bool
    :param is_enabled_by_default: A flag indicating whether the rule is enabled by default.
    :type is_enabled_by_default: bool
    :param is_in_preview: A flag indicating whether the rule is in preview.
    :type is_in_preview: bool
    :param supports_email_notifications: A flag indicating whether email notifications are
     supported for detections for this rule.
    :type supports_email_notifications: bool
    """

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str'},
        'display_name': {'key': 'DisplayName', 'type': 'str'},
        'description': {'key': 'Description', 'type': 'str'},
        'help_url': {'key': 'HelpUrl', 'type': 'str'},
        'is_hidden': {'key': 'IsHidden', 'type': 'bool'},
        'is_enabled_by_default': {'key': 'IsEnabledByDefault', 'type': 'bool'},
        'is_in_preview': {'key': 'IsInPreview', 'type': 'bool'},
        'supports_email_notifications': {'key': 'SupportsEmailNotifications', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        help_url: Optional[str] = None,
        is_hidden: Optional[bool] = None,
        is_enabled_by_default: Optional[bool] = None,
        is_in_preview: Optional[bool] = None,
        supports_email_notifications: Optional[bool] = None,
        **kwargs
    ):
        super(ApplicationInsightsComponentProactiveDetectionConfigurationPropertiesRuleDefinitions, self).__init__(**kwargs)
        self.name = name
        self.display_name = display_name
        self.description = description
        self.help_url = help_url
        self.is_hidden = is_hidden
        self.is_enabled_by_default = is_enabled_by_default
        self.is_in_preview = is_in_preview
        self.supports_email_notifications = supports_email_notifications


class ComponentPurgeBody(msrest.serialization.Model):
    """Describes the body of a purge request for an App Insights component.

    All required parameters must be populated in order to send to Azure.

    :param table: Required. Table from which to purge data.
    :type table: str
    :param filters: Required. The set of columns and filters (queries) to run over them to purge
     the resulting data.
    :type filters:
     list[~azure.mgmt.applicationinsights.v2018_05_01_preview.models.ComponentPurgeBodyFilters]
    """

    _validation = {
        'table': {'required': True},
        'filters': {'required': True},
    }

    _attribute_map = {
        'table': {'key': 'table', 'type': 'str'},
        'filters': {'key': 'filters', 'type': '[ComponentPurgeBodyFilters]'},
    }

    def __init__(
        self,
        *,
        table: str,
        filters: List["ComponentPurgeBodyFilters"],
        **kwargs
    ):
        super(ComponentPurgeBody, self).__init__(**kwargs)
        self.table = table
        self.filters = filters


class ComponentPurgeBodyFilters(msrest.serialization.Model):
    """User-defined filters to return data which will be purged from the table.

    :param column: The column of the table over which the given query should run.
    :type column: str
    :param operator: A query operator to evaluate over the provided column and value(s). Supported
     operators are ==, =~, in, in~, >, >=, <, <=, between, and have the same behavior as they would
     in a KQL query.
    :type operator: str
    :param value: the value for the operator to function over. This can be a number (e.g., > 100),
     a string (timestamp >= '2017-09-01') or array of values.
    :type value: object
    :param key: When filtering over custom dimensions, this key will be used as the name of the
     custom dimension.
    :type key: str
    """

    _attribute_map = {
        'column': {'key': 'column', 'type': 'str'},
        'operator': {'key': 'operator', 'type': 'str'},
        'value': {'key': 'value', 'type': 'object'},
        'key': {'key': 'key', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        column: Optional[str] = None,
        operator: Optional[str] = None,
        value: Optional[object] = None,
        key: Optional[str] = None,
        **kwargs
    ):
        super(ComponentPurgeBodyFilters, self).__init__(**kwargs)
        self.column = column
        self.operator = operator
        self.value = value
        self.key = key


class ComponentPurgeResponse(msrest.serialization.Model):
    """Response containing operationId for a specific purge action.

    All required parameters must be populated in order to send to Azure.

    :param operation_id: Required. Id to use when querying for status for a particular purge
     operation.
    :type operation_id: str
    """

    _validation = {
        'operation_id': {'required': True},
    }

    _attribute_map = {
        'operation_id': {'key': 'operationId', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        operation_id: str,
        **kwargs
    ):
        super(ComponentPurgeResponse, self).__init__(**kwargs)
        self.operation_id = operation_id


class ComponentPurgeStatusResponse(msrest.serialization.Model):
    """Response containing status for a specific purge operation.

    All required parameters must be populated in order to send to Azure.

    :param status: Required. Status of the operation represented by the requested Id. Possible
     values include: "pending", "completed".
    :type status: str or ~azure.mgmt.applicationinsights.v2018_05_01_preview.models.PurgeState
    """

    _validation = {
        'status': {'required': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        status: Union[str, "PurgeState"],
        **kwargs
    ):
        super(ComponentPurgeStatusResponse, self).__init__(**kwargs)
        self.status = status


class PrivateLinkScopedResource(msrest.serialization.Model):
    """The private link scope resource reference.

    :param resource_id: The full resource Id of the private link scope resource.
    :type resource_id: str
    :param scope_id: The private link scope unique Identifier.
    :type scope_id: str
    """

    _attribute_map = {
        'resource_id': {'key': 'ResourceId', 'type': 'str'},
        'scope_id': {'key': 'ScopeId', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        resource_id: Optional[str] = None,
        scope_id: Optional[str] = None,
        **kwargs
    ):
        super(PrivateLinkScopedResource, self).__init__(**kwargs)
        self.resource_id = resource_id
        self.scope_id = scope_id


class TagsResource(msrest.serialization.Model):
    """A container holding only the Tags for a resource, allowing the user to update the tags on a WebTest instance.

    :param tags: A set of tags. Resource tags.
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
        super(TagsResource, self).__init__(**kwargs)
        self.tags = tags
