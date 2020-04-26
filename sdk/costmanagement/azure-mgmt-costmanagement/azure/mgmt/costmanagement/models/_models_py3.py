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


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class CommonExportProperties(Model):
    """The common properties of the export.

    All required parameters must be populated in order to send to Azure.

    :param format: The format of the export being delivered. Possible values
     include: 'Csv'
    :type format: str or ~azure.mgmt.costmanagement.models.FormatType
    :param delivery_info: Required. Has delivery information for the export.
    :type delivery_info: ~azure.mgmt.costmanagement.models.ExportDeliveryInfo
    :param definition: Required. Has definition for the export.
    :type definition: ~azure.mgmt.costmanagement.models.QueryDefinition
    """

    _validation = {
        'delivery_info': {'required': True},
        'definition': {'required': True},
    }

    _attribute_map = {
        'format': {'key': 'format', 'type': 'str'},
        'delivery_info': {'key': 'deliveryInfo', 'type': 'ExportDeliveryInfo'},
        'definition': {'key': 'definition', 'type': 'QueryDefinition'},
    }

    def __init__(self, *, delivery_info, definition, format=None, **kwargs) -> None:
        super(CommonExportProperties, self).__init__(**kwargs)
        self.format = format
        self.delivery_info = delivery_info
        self.definition = definition


class Resource(Model):
    """The Resource model definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar tags: Resource tags.
    :vartype tags: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs) -> None:
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.tags = None


class Dimension(Resource):
    """Dimension.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar tags: Resource tags.
    :vartype tags: dict[str, str]
    :ivar description: Dimension description.
    :vartype description: str
    :ivar filter_enabled: Filter enabled.
    :vartype filter_enabled: bool
    :ivar grouping_enabled: Grouping enabled.
    :vartype grouping_enabled: bool
    :param data:
    :type data: list[str]
    :ivar total: Total number of data for the dimension.
    :vartype total: int
    :ivar category: Dimension category.
    :vartype category: str
    :ivar usage_start: Usage start.
    :vartype usage_start: datetime
    :ivar usage_end: Usage end.
    :vartype usage_end: datetime
    :ivar next_link: The link (url) to the next page of results.
    :vartype next_link: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
        'description': {'readonly': True},
        'filter_enabled': {'readonly': True},
        'grouping_enabled': {'readonly': True},
        'total': {'readonly': True},
        'category': {'readonly': True},
        'usage_start': {'readonly': True},
        'usage_end': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'filter_enabled': {'key': 'properties.filterEnabled', 'type': 'bool'},
        'grouping_enabled': {'key': 'properties.groupingEnabled', 'type': 'bool'},
        'data': {'key': 'properties.data', 'type': '[str]'},
        'total': {'key': 'properties.total', 'type': 'int'},
        'category': {'key': 'properties.category', 'type': 'str'},
        'usage_start': {'key': 'properties.usageStart', 'type': 'iso-8601'},
        'usage_end': {'key': 'properties.usageEnd', 'type': 'iso-8601'},
        'next_link': {'key': 'properties.nextLink', 'type': 'str'},
    }

    def __init__(self, *, data=None, **kwargs) -> None:
        super(Dimension, self).__init__(**kwargs)
        self.description = None
        self.filter_enabled = None
        self.grouping_enabled = None
        self.data = data
        self.total = None
        self.category = None
        self.usage_start = None
        self.usage_end = None
        self.next_link = None


class ErrorDetails(Model):
    """The details of the error.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: Error code.
    :vartype code: str
    :ivar message: Error message indicating why the operation failed.
    :vartype message: str
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(ErrorDetails, self).__init__(**kwargs)
        self.code = None
        self.message = None


class ErrorResponse(Model):
    """Error response indicates that the service is not able to process the
    incoming request. The reason is provided in the error message.
    Some Error responses:
    * 429 TooManyRequests - Request is throttled. Retry after waiting for the
    time specified in the "x-ms-ratelimit-microsoft.consumption-retry-after"
    header.
    * 503 ServiceUnavailable - Service is temporarily unavailable. Retry after
    waiting for the time specified in the "Retry-After" header.

    :param error: The details of the error.
    :type error: ~azure.mgmt.costmanagement.models.ErrorDetails
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorDetails'},
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


class Export(Resource):
    """A export resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar tags: Resource tags.
    :vartype tags: dict[str, str]
    :param format: The format of the export being delivered. Possible values
     include: 'Csv'
    :type format: str or ~azure.mgmt.costmanagement.models.FormatType
    :param delivery_info: Required. Has delivery information for the export.
    :type delivery_info: ~azure.mgmt.costmanagement.models.ExportDeliveryInfo
    :param definition: Required. Has definition for the export.
    :type definition: ~azure.mgmt.costmanagement.models.QueryDefinition
    :param schedule: Has schedule information for the export.
    :type schedule: ~azure.mgmt.costmanagement.models.ExportSchedule
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
        'delivery_info': {'required': True},
        'definition': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'format': {'key': 'properties.format', 'type': 'str'},
        'delivery_info': {'key': 'properties.deliveryInfo', 'type': 'ExportDeliveryInfo'},
        'definition': {'key': 'properties.definition', 'type': 'QueryDefinition'},
        'schedule': {'key': 'properties.schedule', 'type': 'ExportSchedule'},
    }

    def __init__(self, *, delivery_info, definition, format=None, schedule=None, **kwargs) -> None:
        super(Export, self).__init__(**kwargs)
        self.format = format
        self.delivery_info = delivery_info
        self.definition = definition
        self.schedule = schedule


class ExportDeliveryDestination(Model):
    """The destination information for the delivery of the export. To allow access
    to a storage account, you must register the account's subscription with the
    Microsoft.CostManagementExports resource provider. This is required once
    per subscription. When creating an export in the Azure portal, it is done
    automatically, however API users need to register the subscription. For
    more information see
    https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-supported-services
    .

    All required parameters must be populated in order to send to Azure.

    :param resource_id: Required. The resource id of the storage account where
     exports will be delivered.
    :type resource_id: str
    :param container: Required. The name of the container where exports will
     be uploaded.
    :type container: str
    :param root_folder_path: The name of the directory where exports will be
     uploaded.
    :type root_folder_path: str
    """

    _validation = {
        'resource_id': {'required': True},
        'container': {'required': True},
    }

    _attribute_map = {
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'container': {'key': 'container', 'type': 'str'},
        'root_folder_path': {'key': 'rootFolderPath', 'type': 'str'},
    }

    def __init__(self, *, resource_id: str, container: str, root_folder_path: str=None, **kwargs) -> None:
        super(ExportDeliveryDestination, self).__init__(**kwargs)
        self.resource_id = resource_id
        self.container = container
        self.root_folder_path = root_folder_path


class ExportDeliveryInfo(Model):
    """The delivery information associated with a export.

    All required parameters must be populated in order to send to Azure.

    :param destination: Required. Has destination for the export being
     delivered.
    :type destination:
     ~azure.mgmt.costmanagement.models.ExportDeliveryDestination
    """

    _validation = {
        'destination': {'required': True},
    }

    _attribute_map = {
        'destination': {'key': 'destination', 'type': 'ExportDeliveryDestination'},
    }

    def __init__(self, *, destination, **kwargs) -> None:
        super(ExportDeliveryInfo, self).__init__(**kwargs)
        self.destination = destination


class ExportExecution(Resource):
    """A export execution.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar tags: Resource tags.
    :vartype tags: dict[str, str]
    :param execution_type: The type of the export execution. Possible values
     include: 'OnDemand', 'Scheduled'
    :type execution_type: str or
     ~azure.mgmt.costmanagement.models.ExecutionType
    :param status: The status of the export execution. Possible values
     include: 'Queued', 'InProgress', 'Completed', 'Failed', 'Timeout',
     'NewDataNotAvailable', 'DataNotAvailable'
    :type status: str or ~azure.mgmt.costmanagement.models.ExecutionStatus
    :param submitted_by: The identifier for the entity that executed the
     export. For OnDemand executions, it is the email id. For Scheduled
     executions, it is the constant value - System.
    :type submitted_by: str
    :param submitted_time: The time when export was queued to be executed.
    :type submitted_time: datetime
    :param processing_start_time: The time when export was picked up to be
     executed.
    :type processing_start_time: datetime
    :param processing_end_time: The time when export execution finished.
    :type processing_end_time: datetime
    :param file_name: The name of the file export got written to.
    :type file_name: str
    :param run_settings:
    :type run_settings:
     ~azure.mgmt.costmanagement.models.CommonExportProperties
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'execution_type': {'key': 'properties.executionType', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'submitted_by': {'key': 'properties.submittedBy', 'type': 'str'},
        'submitted_time': {'key': 'properties.submittedTime', 'type': 'iso-8601'},
        'processing_start_time': {'key': 'properties.processingStartTime', 'type': 'iso-8601'},
        'processing_end_time': {'key': 'properties.processingEndTime', 'type': 'iso-8601'},
        'file_name': {'key': 'properties.fileName', 'type': 'str'},
        'run_settings': {'key': 'properties.runSettings', 'type': 'CommonExportProperties'},
    }

    def __init__(self, *, execution_type=None, status=None, submitted_by: str=None, submitted_time=None, processing_start_time=None, processing_end_time=None, file_name: str=None, run_settings=None, **kwargs) -> None:
        super(ExportExecution, self).__init__(**kwargs)
        self.execution_type = execution_type
        self.status = status
        self.submitted_by = submitted_by
        self.submitted_time = submitted_time
        self.processing_start_time = processing_start_time
        self.processing_end_time = processing_end_time
        self.file_name = file_name
        self.run_settings = run_settings


class ExportExecutionListResult(Model):
    """Result of listing exports execution history of a export by name.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar value: The list of export executions.
    :vartype value: list[~azure.mgmt.costmanagement.models.ExportExecution]
    """

    _validation = {
        'value': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ExportExecution]'},
    }

    def __init__(self, **kwargs) -> None:
        super(ExportExecutionListResult, self).__init__(**kwargs)
        self.value = None


class ExportListResult(Model):
    """Result of listing exports. It contains a list of available exports in the
    scope provided.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar value: The list of exports.
    :vartype value: list[~azure.mgmt.costmanagement.models.Export]
    """

    _validation = {
        'value': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Export]'},
    }

    def __init__(self, **kwargs) -> None:
        super(ExportListResult, self).__init__(**kwargs)
        self.value = None


class ExportRecurrencePeriod(Model):
    """The start and end date for recurrence schedule.

    All required parameters must be populated in order to send to Azure.

    :param from_property: Required. The start date of recurrence.
    :type from_property: datetime
    :param to: The end date of recurrence.
    :type to: datetime
    """

    _validation = {
        'from_property': {'required': True},
    }

    _attribute_map = {
        'from_property': {'key': 'from', 'type': 'iso-8601'},
        'to': {'key': 'to', 'type': 'iso-8601'},
    }

    def __init__(self, *, from_property, to=None, **kwargs) -> None:
        super(ExportRecurrencePeriod, self).__init__(**kwargs)
        self.from_property = from_property
        self.to = to


class ExportSchedule(Model):
    """The schedule associated with a export.

    All required parameters must be populated in order to send to Azure.

    :param status: The status of the schedule. Whether active or not. If
     inactive, the export's scheduled execution is paused. Possible values
     include: 'Active', 'Inactive'
    :type status: str or ~azure.mgmt.costmanagement.models.StatusType
    :param recurrence: Required. The schedule recurrence. Possible values
     include: 'Daily', 'Weekly', 'Monthly', 'Annually'
    :type recurrence: str or ~azure.mgmt.costmanagement.models.RecurrenceType
    :param recurrence_period: Has start and end date of the recurrence. The
     start date must be in future. If present, the end date must be greater
     than start date.
    :type recurrence_period:
     ~azure.mgmt.costmanagement.models.ExportRecurrencePeriod
    """

    _validation = {
        'recurrence': {'required': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'recurrence': {'key': 'recurrence', 'type': 'str'},
        'recurrence_period': {'key': 'recurrencePeriod', 'type': 'ExportRecurrencePeriod'},
    }

    def __init__(self, *, recurrence, status=None, recurrence_period=None, **kwargs) -> None:
        super(ExportSchedule, self).__init__(**kwargs)
        self.status = status
        self.recurrence = recurrence
        self.recurrence_period = recurrence_period


class Operation(Model):
    """A Cost management REST API operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Operation name: {provider}/{resource}/{operation}.
    :vartype name: str
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.costmanagement.models.OperationDisplay
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

    :ivar provider: Service provider: Microsoft.CostManagement.
    :vartype provider: str
    :ivar resource: Resource on which the operation is performed: Dimensions,
     Query.
    :vartype resource: str
    :ivar operation: Operation type: Read, write, delete, etc.
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


class QueryAggregation(Model):
    """The aggregation expression to be used in the query.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the column to aggregate.
    :type name: str
    :ivar function: Required. The name of the aggregation function to use.
     Default value: "Sum" .
    :vartype function: str
    """

    _validation = {
        'name': {'required': True},
        'function': {'required': True, 'constant': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'function': {'key': 'function', 'type': 'str'},
    }

    function = "Sum"

    def __init__(self, *, name: str, **kwargs) -> None:
        super(QueryAggregation, self).__init__(**kwargs)
        self.name = name


class QueryColumn(Model):
    """QueryColumn.

    :param name: The name of column.
    :type name: str
    :param type: The type of column.
    :type type: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, type: str=None, **kwargs) -> None:
        super(QueryColumn, self).__init__(**kwargs)
        self.name = name
        self.type = type


class QueryComparisonExpression(Model):
    """The comparison expression to be used in the query.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the column to use in comparison.
    :type name: str
    :ivar operator: Required. The operator to use for comparison. Default
     value: "In" .
    :vartype operator: str
    :param values: Required. Array of values to use for comparison
    :type values: list[str]
    """

    _validation = {
        'name': {'required': True},
        'operator': {'required': True, 'constant': True},
        'values': {'required': True, 'min_items': 1},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'operator': {'key': 'operator', 'type': 'str'},
        'values': {'key': 'values', 'type': '[str]'},
    }

    operator = "In"

    def __init__(self, *, name: str, values, **kwargs) -> None:
        super(QueryComparisonExpression, self).__init__(**kwargs)
        self.name = name
        self.values = values


class QueryDataset(Model):
    """The definition of data present in the query.

    :param granularity: The granularity of rows in the query. Possible values
     include: 'Daily'
    :type granularity: str or
     ~azure.mgmt.costmanagement.models.GranularityType
    :param configuration: Has configuration information for the data in the
     export. The configuration will be ignored if aggregation and grouping are
     provided.
    :type configuration:
     ~azure.mgmt.costmanagement.models.QueryDatasetConfiguration
    :param aggregation: Dictionary of aggregation expression to use in the
     query. The key of each item in the dictionary is the alias for the
     aggregated column. Query can have up to 2 aggregation clauses.
    :type aggregation: dict[str,
     ~azure.mgmt.costmanagement.models.QueryAggregation]
    :param grouping: Array of group by expression to use in the query. Query
     can have up to 2 group by clauses.
    :type grouping: list[~azure.mgmt.costmanagement.models.QueryGrouping]
    :param filter: Has filter expression to use in the query.
    :type filter: ~azure.mgmt.costmanagement.models.QueryFilter
    """

    _validation = {
        'grouping': {'max_items': 2},
    }

    _attribute_map = {
        'granularity': {'key': 'granularity', 'type': 'str'},
        'configuration': {'key': 'configuration', 'type': 'QueryDatasetConfiguration'},
        'aggregation': {'key': 'aggregation', 'type': '{QueryAggregation}'},
        'grouping': {'key': 'grouping', 'type': '[QueryGrouping]'},
        'filter': {'key': 'filter', 'type': 'QueryFilter'},
    }

    def __init__(self, *, granularity=None, configuration=None, aggregation=None, grouping=None, filter=None, **kwargs) -> None:
        super(QueryDataset, self).__init__(**kwargs)
        self.granularity = granularity
        self.configuration = configuration
        self.aggregation = aggregation
        self.grouping = grouping
        self.filter = filter


class QueryDatasetConfiguration(Model):
    """The configuration of dataset in the query.

    :param columns: Array of column names to be included in the query. Any
     valid query column name is allowed. If not provided, then query includes
     all columns.
    :type columns: list[str]
    """

    _attribute_map = {
        'columns': {'key': 'columns', 'type': '[str]'},
    }

    def __init__(self, *, columns=None, **kwargs) -> None:
        super(QueryDatasetConfiguration, self).__init__(**kwargs)
        self.columns = columns


class QueryDefinition(Model):
    """The definition of a query.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. The type of the query. Possible values include:
     'Usage', 'ActualCost', 'AmortizedCost'
    :type type: str or ~azure.mgmt.costmanagement.models.ExportType
    :param timeframe: Required. The time frame for pulling data for the query.
     If custom, then a specific time period must be provided. Possible values
     include: 'MonthToDate', 'BillingMonthToDate', 'TheLastMonth',
     'TheLastBillingMonth', 'WeekToDate', 'Custom'
    :type timeframe: str or ~azure.mgmt.costmanagement.models.TimeframeType
    :param time_period: Has time period for pulling data for the query.
    :type time_period: ~azure.mgmt.costmanagement.models.QueryTimePeriod
    :param dataset: Has definition for data in this query.
    :type dataset: ~azure.mgmt.costmanagement.models.QueryDataset
    """

    _validation = {
        'type': {'required': True},
        'timeframe': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'timeframe': {'key': 'timeframe', 'type': 'str'},
        'time_period': {'key': 'timePeriod', 'type': 'QueryTimePeriod'},
        'dataset': {'key': 'dataset', 'type': 'QueryDataset'},
    }

    def __init__(self, *, type, timeframe, time_period=None, dataset=None, **kwargs) -> None:
        super(QueryDefinition, self).__init__(**kwargs)
        self.type = type
        self.timeframe = timeframe
        self.time_period = time_period
        self.dataset = dataset


class QueryFilter(Model):
    """The filter expression to be used in the export.

    :param and_property: The logical "AND" expression. Must have at least 2
     items.
    :type and_property: list[~azure.mgmt.costmanagement.models.QueryFilter]
    :param or_property: The logical "OR" expression. Must have at least 2
     items.
    :type or_property: list[~azure.mgmt.costmanagement.models.QueryFilter]
    :param not_property: The logical "NOT" expression.
    :type not_property: ~azure.mgmt.costmanagement.models.QueryFilter
    :param dimension: Has comparison expression for a dimension
    :type dimension:
     ~azure.mgmt.costmanagement.models.QueryComparisonExpression
    :param tag: Has comparison expression for a tag
    :type tag: ~azure.mgmt.costmanagement.models.QueryComparisonExpression
    """

    _validation = {
        'and_property': {'min_items': 2},
        'or_property': {'min_items': 2},
    }

    _attribute_map = {
        'and_property': {'key': 'and', 'type': '[QueryFilter]'},
        'or_property': {'key': 'or', 'type': '[QueryFilter]'},
        'not_property': {'key': 'not', 'type': 'QueryFilter'},
        'dimension': {'key': 'dimension', 'type': 'QueryComparisonExpression'},
        'tag': {'key': 'tag', 'type': 'QueryComparisonExpression'},
    }

    def __init__(self, *, and_property=None, or_property=None, not_property=None, dimension=None, tag=None, **kwargs) -> None:
        super(QueryFilter, self).__init__(**kwargs)
        self.and_property = and_property
        self.or_property = or_property
        self.not_property = not_property
        self.dimension = dimension
        self.tag = tag


class QueryGrouping(Model):
    """The group by expression to be used in the query.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Has type of the column to group. Possible values
     include: 'Tag', 'Dimension'
    :type type: str or ~azure.mgmt.costmanagement.models.QueryColumnType
    :param name: Required. The name of the column to group.
    :type name: str
    """

    _validation = {
        'type': {'required': True},
        'name': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, type, name: str, **kwargs) -> None:
        super(QueryGrouping, self).__init__(**kwargs)
        self.type = type
        self.name = name


class QueryResult(Resource):
    """Result of query. It contains all columns listed under groupings and
    aggregation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar tags: Resource tags.
    :vartype tags: dict[str, str]
    :param next_link: The link (url) to the next page of results.
    :type next_link: str
    :param columns: Array of columns
    :type columns: list[~azure.mgmt.costmanagement.models.QueryColumn]
    :param rows: Array of rows
    :type rows: list[list[object]]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'next_link': {'key': 'properties.nextLink', 'type': 'str'},
        'columns': {'key': 'properties.columns', 'type': '[QueryColumn]'},
        'rows': {'key': 'properties.rows', 'type': '[[object]]'},
    }

    def __init__(self, *, next_link: str=None, columns=None, rows=None, **kwargs) -> None:
        super(QueryResult, self).__init__(**kwargs)
        self.next_link = next_link
        self.columns = columns
        self.rows = rows


class QueryTimePeriod(Model):
    """The start and end date for pulling data for the query.

    All required parameters must be populated in order to send to Azure.

    :param from_property: Required. The start date to pull data from.
    :type from_property: datetime
    :param to: Required. The end date to pull data to.
    :type to: datetime
    """

    _validation = {
        'from_property': {'required': True},
        'to': {'required': True},
    }

    _attribute_map = {
        'from_property': {'key': 'from', 'type': 'iso-8601'},
        'to': {'key': 'to', 'type': 'iso-8601'},
    }

    def __init__(self, *, from_property, to, **kwargs) -> None:
        super(QueryTimePeriod, self).__init__(**kwargs)
        self.from_property = from_property
        self.to = to
