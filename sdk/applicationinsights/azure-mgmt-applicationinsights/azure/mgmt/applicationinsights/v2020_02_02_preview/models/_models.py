# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import msrest.serialization


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
        **kwargs
    ):
        super(ComponentsResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = kwargs['location']
        self.tags = kwargs.get('tags', None)


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
     ~azure.mgmt.applicationinsights.v2020_02_02_preview.models.ApplicationType
    :param flow_type: Used by the Application Insights system to determine what kind of flow this
     component was created by. This is to be set to 'Bluefield' when creating/updating a component
     via the REST API. Possible values include: "Bluefield". Default value: "Bluefield".
    :type flow_type: str or ~azure.mgmt.applicationinsights.v2020_02_02_preview.models.FlowType
    :param request_source: Describes what tool created this Application Insights component.
     Customers using this API should set this to the default 'rest'. Possible values include:
     "rest". Default value: "rest".
    :type request_source: str or
     ~azure.mgmt.applicationinsights.v2020_02_02_preview.models.RequestSource
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
    :ivar retention_in_days: Retention period in days.
    :vartype retention_in_days: int
    :param disable_ip_masking: Disable IP masking.
    :type disable_ip_masking: bool
    :param immediate_purge_data_on30_days: Purge data immediately after 30 days.
    :type immediate_purge_data_on30_days: bool
    :param workspace_resource_id: ResourceId of the log analytics workspace which the data will be
     ingested to.
    :type workspace_resource_id: str
    :ivar la_migration_date: The date which the component got migrated to LA, in ISO 8601 format.
    :vartype la_migration_date: ~datetime.datetime
    :ivar private_link_scoped_resources: List of linked private link scope resources.
    :vartype private_link_scoped_resources:
     list[~azure.mgmt.applicationinsights.v2020_02_02_preview.models.PrivateLinkScopedResource]
    :param public_network_access_for_ingestion: The network access type for accessing Application
     Insights ingestion. Possible values include: "Enabled", "Disabled". Default value: "Enabled".
    :type public_network_access_for_ingestion: str or
     ~azure.mgmt.applicationinsights.v2020_02_02_preview.models.PublicNetworkAccessType
    :param public_network_access_for_query: The network access type for accessing Application
     Insights query. Possible values include: "Enabled", "Disabled". Default value: "Enabled".
    :type public_network_access_for_query: str or
     ~azure.mgmt.applicationinsights.v2020_02_02_preview.models.PublicNetworkAccessType
    :param ingestion_mode: Indicates the flow of the ingestion. Possible values include:
     "ApplicationInsights", "ApplicationInsightsWithDiagnosticSettings", "LogAnalytics". Default
     value: "LogAnalytics".
    :type ingestion_mode: str or
     ~azure.mgmt.applicationinsights.v2020_02_02_preview.models.IngestionMode
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
        'retention_in_days': {'readonly': True},
        'la_migration_date': {'readonly': True},
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
        'workspace_resource_id': {'key': 'properties.WorkspaceResourceId', 'type': 'str'},
        'la_migration_date': {'key': 'properties.LaMigrationDate', 'type': 'iso-8601'},
        'private_link_scoped_resources': {'key': 'properties.PrivateLinkScopedResources', 'type': '[PrivateLinkScopedResource]'},
        'public_network_access_for_ingestion': {'key': 'properties.publicNetworkAccessForIngestion', 'type': 'str'},
        'public_network_access_for_query': {'key': 'properties.publicNetworkAccessForQuery', 'type': 'str'},
        'ingestion_mode': {'key': 'properties.IngestionMode', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ApplicationInsightsComponent, self).__init__(**kwargs)
        self.kind = kwargs['kind']
        self.application_id = None
        self.app_id = None
        self.application_type = kwargs.get('application_type', "web")
        self.flow_type = kwargs.get('flow_type', "Bluefield")
        self.request_source = kwargs.get('request_source', "rest")
        self.instrumentation_key = None
        self.creation_date = None
        self.tenant_id = None
        self.hockey_app_id = kwargs.get('hockey_app_id', None)
        self.hockey_app_token = None
        self.provisioning_state = None
        self.sampling_percentage = kwargs.get('sampling_percentage', None)
        self.connection_string = None
        self.retention_in_days = None
        self.disable_ip_masking = kwargs.get('disable_ip_masking', None)
        self.immediate_purge_data_on30_days = kwargs.get('immediate_purge_data_on30_days', None)
        self.workspace_resource_id = kwargs.get('workspace_resource_id', None)
        self.la_migration_date = None
        self.private_link_scoped_resources = None
        self.public_network_access_for_ingestion = kwargs.get('public_network_access_for_ingestion', "Enabled")
        self.public_network_access_for_query = kwargs.get('public_network_access_for_query', "Enabled")
        self.ingestion_mode = kwargs.get('ingestion_mode', "LogAnalytics")


class ApplicationInsightsComponentListResult(msrest.serialization.Model):
    """Describes the list of Application Insights Resources.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. List of Application Insights component definitions.
    :type value:
     list[~azure.mgmt.applicationinsights.v2020_02_02_preview.models.ApplicationInsightsComponent]
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
        **kwargs
    ):
        super(ApplicationInsightsComponentListResult, self).__init__(**kwargs)
        self.value = kwargs['value']
        self.next_link = kwargs.get('next_link', None)


class ComponentPurgeBody(msrest.serialization.Model):
    """Describes the body of a purge request for an App Insights component.

    All required parameters must be populated in order to send to Azure.

    :param table: Required. Table from which to purge data.
    :type table: str
    :param filters: Required. The set of columns and filters (queries) to run over them to purge
     the resulting data.
    :type filters:
     list[~azure.mgmt.applicationinsights.v2020_02_02_preview.models.ComponentPurgeBodyFilters]
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
        **kwargs
    ):
        super(ComponentPurgeBody, self).__init__(**kwargs)
        self.table = kwargs['table']
        self.filters = kwargs['filters']


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
        **kwargs
    ):
        super(ComponentPurgeBodyFilters, self).__init__(**kwargs)
        self.column = kwargs.get('column', None)
        self.operator = kwargs.get('operator', None)
        self.value = kwargs.get('value', None)
        self.key = kwargs.get('key', None)


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
        **kwargs
    ):
        super(ComponentPurgeResponse, self).__init__(**kwargs)
        self.operation_id = kwargs['operation_id']


class ComponentPurgeStatusResponse(msrest.serialization.Model):
    """Response containing status for a specific purge operation.

    All required parameters must be populated in order to send to Azure.

    :param status: Required. Status of the operation represented by the requested Id. Possible
     values include: "pending", "completed".
    :type status: str or ~azure.mgmt.applicationinsights.v2020_02_02_preview.models.PurgeState
    """

    _validation = {
        'status': {'required': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ComponentPurgeStatusResponse, self).__init__(**kwargs)
        self.status = kwargs['status']


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
        **kwargs
    ):
        super(PrivateLinkScopedResource, self).__init__(**kwargs)
        self.resource_id = kwargs.get('resource_id', None)
        self.scope_id = kwargs.get('scope_id', None)


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
        **kwargs
    ):
        super(TagsResource, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
