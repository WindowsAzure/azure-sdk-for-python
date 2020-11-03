# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class MonitorDomain(msrest.serialization.Model):
    """The abstract common base of all domains.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param version: Required. Schema version.
    :type version: int
    """

    _validation = {
        'version': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'version': {'key': 'ver', 'type': 'int'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MonitorDomain, self).__init__(**kwargs)
        self.additional_properties = kwargs.get('additional_properties', None)
        self.version = kwargs.get('version', 2)


class AvailabilityData(MonitorDomain):
    """Instances of AvailabilityData represent the result of executing an availability test.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param version: Required. Schema version.
    :type version: int
    :param id: Required. Identifier of a test run. Use it to correlate steps of test run and
     telemetry generated by the service.
    :type id: str
    :param name: Required. Name of the test that these availability results represent.
    :type name: str
    :param duration: Required. Duration in format: DD.HH:MM:SS.MMMMMM. Must be less than 1000 days.
    :type duration: str
    :param success: Required. Success flag.
    :type success: bool
    :param run_location: Name of the location where the test was run from.
    :type run_location: str
    :param message: Diagnostic message for the result.
    :type message: str
    :param properties: Collection of custom properties.
    :type properties: dict[str, str]
    :param measurements: Collection of custom measurements.
    :type measurements: dict[str, float]
    """

    _validation = {
        'version': {'required': True},
        'id': {'required': True, 'max_length': 512, 'min_length': 0},
        'name': {'required': True, 'max_length': 1024, 'min_length': 0},
        'duration': {'required': True},
        'success': {'required': True},
        'run_location': {'max_length': 1024, 'min_length': 0},
        'message': {'max_length': 8192, 'min_length': 0},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'version': {'key': 'ver', 'type': 'int'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'duration': {'key': 'duration', 'type': 'str'},
        'success': {'key': 'success', 'type': 'bool'},
        'run_location': {'key': 'runLocation', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'properties': {'key': 'properties', 'type': '{str}'},
        'measurements': {'key': 'measurements', 'type': '{float}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AvailabilityData, self).__init__(**kwargs)
        self.id = kwargs['id']
        self.name = kwargs['name']
        self.duration = kwargs['duration']
        self.success = kwargs['success']
        self.run_location = kwargs.get('run_location', None)
        self.message = kwargs.get('message', None)
        self.properties = kwargs.get('properties', None)
        self.measurements = kwargs.get('measurements', None)


class MessageData(MonitorDomain):
    """Instances of Message represent printf-like trace statements that are text-searched. Log4Net, NLog and other text-based log file entries are translated into instances of this type. The message does not have measurements.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param version: Required. Schema version.
    :type version: int
    :param message: Required. Trace message.
    :type message: str
    :param severity_level: Trace severity level. Possible values include: "Verbose", "Information",
     "Warning", "Error", "Critical".
    :type severity_level: str or ~azure_monitor_client.models.SeverityLevel
    :param properties: Collection of custom properties.
    :type properties: dict[str, str]
    :param measurements: Collection of custom measurements.
    :type measurements: dict[str, float]
    """

    _validation = {
        'version': {'required': True},
        'message': {'required': True, 'max_length': 32768, 'min_length': 0},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'version': {'key': 'ver', 'type': 'int'},
        'message': {'key': 'message', 'type': 'str'},
        'severity_level': {'key': 'severityLevel', 'type': 'str'},
        'properties': {'key': 'properties', 'type': '{str}'},
        'measurements': {'key': 'measurements', 'type': '{float}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MessageData, self).__init__(**kwargs)
        self.message = kwargs['message']
        self.severity_level = kwargs.get('severity_level', None)
        self.properties = kwargs.get('properties', None)
        self.measurements = kwargs.get('measurements', None)


class MetricDataPoint(msrest.serialization.Model):
    """Metric data single measurement.

    All required parameters must be populated in order to send to Azure.

    :param namespace: Namespace of the metric.
    :type namespace: str
    :param name: Required. Name of the metric.
    :type name: str
    :param data_point_type: Metric type. Single measurement or the aggregated value. Possible
     values include: "Measurement", "Aggregation".
    :type data_point_type: str or ~azure_monitor_client.models.DataPointType
    :param value: Required. Single value for measurement. Sum of individual measurements for the
     aggregation.
    :type value: float
    :param count: Metric weight of the aggregated metric. Should not be set for a measurement.
    :type count: int
    :param min: Minimum value of the aggregated metric. Should not be set for a measurement.
    :type min: float
    :param max: Maximum value of the aggregated metric. Should not be set for a measurement.
    :type max: float
    :param std_dev: Standard deviation of the aggregated metric. Should not be set for a
     measurement.
    :type std_dev: float
    """

    _validation = {
        'namespace': {'max_length': 256, 'min_length': 0},
        'name': {'required': True, 'max_length': 1024, 'min_length': 0},
        'value': {'required': True},
    }

    _attribute_map = {
        'namespace': {'key': 'ns', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'data_point_type': {'key': 'kind', 'type': 'str'},
        'value': {'key': 'value', 'type': 'float'},
        'count': {'key': 'count', 'type': 'int'},
        'min': {'key': 'min', 'type': 'float'},
        'max': {'key': 'max', 'type': 'float'},
        'std_dev': {'key': 'stdDev', 'type': 'float'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MetricDataPoint, self).__init__(**kwargs)
        self.namespace = kwargs.get('namespace', None)
        self.name = kwargs['name']
        self.data_point_type = kwargs.get('data_point_type', None)
        self.value = kwargs['value']
        self.count = kwargs.get('count', None)
        self.min = kwargs.get('min', None)
        self.max = kwargs.get('max', None)
        self.std_dev = kwargs.get('std_dev', None)


class MetricsData(MonitorDomain):
    """An instance of the Metric item is a list of measurements (single data points) and/or aggregations.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param version: Required. Schema version.
    :type version: int
    :param metrics: Required. List of metrics. Only one metric in the list is currently supported
     by Application Insights storage. If multiple data points were sent only the first one will be
     used.
    :type metrics: list[~azure_monitor_client.models.MetricDataPoint]
    :param properties: Collection of custom properties.
    :type properties: dict[str, str]
    """

    _validation = {
        'version': {'required': True},
        'metrics': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'version': {'key': 'ver', 'type': 'int'},
        'metrics': {'key': 'metrics', 'type': '[MetricDataPoint]'},
        'properties': {'key': 'properties', 'type': '{str}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MetricsData, self).__init__(**kwargs)
        self.metrics = kwargs['metrics']
        self.properties = kwargs.get('properties', None)


class MonitorBase(msrest.serialization.Model):
    """Data struct to contain only C section with custom fields.

    :param base_type: Name of item (B section) if any. If telemetry data is derived straight from
     this, this should be null.
    :type base_type: str
    :param base_data: The data payload for the telemetry request.
    :type base_data: ~azure_monitor_client.models.MonitorDomain
    """

    _attribute_map = {
        'base_type': {'key': 'baseType', 'type': 'str'},
        'base_data': {'key': 'baseData', 'type': 'MonitorDomain'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MonitorBase, self).__init__(**kwargs)
        self.base_type = kwargs.get('base_type', None)
        self.base_data = kwargs.get('base_data', None)


class PageViewData(MonitorDomain):
    """An instance of PageView represents a generic action on a page like a button click. It is also the base type for PageView.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param version: Required. Schema version.
    :type version: int
    :param id: Required. Identifier of a page view instance. Used for correlation between page view
     and other telemetry items.
    :type id: str
    :param name: Required. Event name. Keep it low cardinality to allow proper grouping and useful
     metrics.
    :type name: str
    :param url: Request URL with all query string parameters.
    :type url: str
    :param duration: Request duration in format: DD.HH:MM:SS.MMMMMM. For a page view
     (PageViewData), this is the duration. For a page view with performance information
     (PageViewPerfData), this is the page load time. Must be less than 1000 days.
    :type duration: str
    :param referred_uri: Fully qualified page URI or URL of the referring page; if unknown, leave
     blank.
    :type referred_uri: str
    :param properties: Collection of custom properties.
    :type properties: dict[str, str]
    :param measurements: Collection of custom measurements.
    :type measurements: dict[str, float]
    """

    _validation = {
        'version': {'required': True},
        'id': {'required': True, 'max_length': 512, 'min_length': 0},
        'name': {'required': True, 'max_length': 1024, 'min_length': 0},
        'url': {'max_length': 2048, 'min_length': 0},
        'referred_uri': {'max_length': 2048, 'min_length': 0},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'version': {'key': 'ver', 'type': 'int'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'duration': {'key': 'duration', 'type': 'str'},
        'referred_uri': {'key': 'referredUri', 'type': 'str'},
        'properties': {'key': 'properties', 'type': '{str}'},
        'measurements': {'key': 'measurements', 'type': '{float}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PageViewData, self).__init__(**kwargs)
        self.id = kwargs['id']
        self.name = kwargs['name']
        self.url = kwargs.get('url', None)
        self.duration = kwargs.get('duration', None)
        self.referred_uri = kwargs.get('referred_uri', None)
        self.properties = kwargs.get('properties', None)
        self.measurements = kwargs.get('measurements', None)


class PageViewPerfData(MonitorDomain):
    """An instance of PageViewPerf represents: a page view with no performance data, a page view with performance data, or just the performance data of an earlier page request.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param version: Required. Schema version.
    :type version: int
    :param id: Required. Identifier of a page view instance. Used for correlation between page view
     and other telemetry items.
    :type id: str
    :param name: Required. Event name. Keep it low cardinality to allow proper grouping and useful
     metrics.
    :type name: str
    :param url: Request URL with all query string parameters.
    :type url: str
    :param duration: Request duration in format: DD.HH:MM:SS.MMMMMM. For a page view
     (PageViewData), this is the duration. For a page view with performance information
     (PageViewPerfData), this is the page load time. Must be less than 1000 days.
    :type duration: str
    :param perf_total: Performance total in TimeSpan 'G' (general long) format: d:hh:mm:ss.fffffff.
    :type perf_total: str
    :param network_connect: Network connection time in TimeSpan 'G' (general long) format:
     d:hh:mm:ss.fffffff.
    :type network_connect: str
    :param sent_request: Sent request time in TimeSpan 'G' (general long) format:
     d:hh:mm:ss.fffffff.
    :type sent_request: str
    :param received_response: Received response time in TimeSpan 'G' (general long) format:
     d:hh:mm:ss.fffffff.
    :type received_response: str
    :param dom_processing: DOM processing time in TimeSpan 'G' (general long) format:
     d:hh:mm:ss.fffffff.
    :type dom_processing: str
    :param properties: Collection of custom properties.
    :type properties: dict[str, str]
    :param measurements: Collection of custom measurements.
    :type measurements: dict[str, float]
    """

    _validation = {
        'version': {'required': True},
        'id': {'required': True, 'max_length': 512, 'min_length': 0},
        'name': {'required': True, 'max_length': 1024, 'min_length': 0},
        'url': {'max_length': 2048, 'min_length': 0},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'version': {'key': 'ver', 'type': 'int'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'duration': {'key': 'duration', 'type': 'str'},
        'perf_total': {'key': 'perfTotal', 'type': 'str'},
        'network_connect': {'key': 'networkConnect', 'type': 'str'},
        'sent_request': {'key': 'sentRequest', 'type': 'str'},
        'received_response': {'key': 'receivedResponse', 'type': 'str'},
        'dom_processing': {'key': 'domProcessing', 'type': 'str'},
        'properties': {'key': 'properties', 'type': '{str}'},
        'measurements': {'key': 'measurements', 'type': '{float}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PageViewPerfData, self).__init__(**kwargs)
        self.id = kwargs['id']
        self.name = kwargs['name']
        self.url = kwargs.get('url', None)
        self.duration = kwargs.get('duration', None)
        self.perf_total = kwargs.get('perf_total', None)
        self.network_connect = kwargs.get('network_connect', None)
        self.sent_request = kwargs.get('sent_request', None)
        self.received_response = kwargs.get('received_response', None)
        self.dom_processing = kwargs.get('dom_processing', None)
        self.properties = kwargs.get('properties', None)
        self.measurements = kwargs.get('measurements', None)


class RemoteDependencyData(MonitorDomain):
    """An instance of Remote Dependency represents an interaction of the monitored component with a remote component/service like SQL or an HTTP endpoint.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param version: Required. Schema version.
    :type version: int
    :param id: Identifier of a dependency call instance. Used for correlation with the request
     telemetry item corresponding to this dependency call.
    :type id: str
    :param name: Required. Name of the command initiated with this dependency call. Low cardinality
     value. Examples are stored procedure name and URL path template.
    :type name: str
    :param result_code: Result code of a dependency call. Examples are SQL error code and HTTP
     status code.
    :type result_code: str
    :param data: Command initiated by this dependency call. Examples are SQL statement and HTTP URL
     with all query parameters.
    :type data: str
    :param type: Dependency type name. Very low cardinality value for logical grouping of
     dependencies and interpretation of other fields like commandName and resultCode. Examples are
     SQL, Azure table, and HTTP.
    :type type: str
    :param target: Target site of a dependency call. Examples are server name, host address.
    :type target: str
    :param duration: Required. Request duration in format: DD.HH:MM:SS.MMMMMM. Must be less than
     1000 days.
    :type duration: str
    :param success: Indication of successful or unsuccessful call.
    :type success: bool
    :param properties: Collection of custom properties.
    :type properties: dict[str, str]
    :param measurements: Collection of custom measurements.
    :type measurements: dict[str, float]
    """

    _validation = {
        'version': {'required': True},
        'id': {'max_length': 512, 'min_length': 0},
        'name': {'required': True, 'max_length': 1024, 'min_length': 0},
        'result_code': {'max_length': 1024, 'min_length': 0},
        'data': {'max_length': 8192, 'min_length': 0},
        'type': {'max_length': 1024, 'min_length': 0},
        'target': {'max_length': 1024, 'min_length': 0},
        'duration': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'version': {'key': 'ver', 'type': 'int'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'result_code': {'key': 'resultCode', 'type': 'str'},
        'data': {'key': 'data', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'duration': {'key': 'duration', 'type': 'str'},
        'success': {'key': 'success', 'type': 'bool'},
        'properties': {'key': 'properties', 'type': '{str}'},
        'measurements': {'key': 'measurements', 'type': '{float}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RemoteDependencyData, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.name = kwargs['name']
        self.result_code = kwargs.get('result_code', None)
        self.data = kwargs.get('data', None)
        self.type = kwargs.get('type', None)
        self.target = kwargs.get('target', None)
        self.duration = kwargs['duration']
        self.success = kwargs.get('success', True)
        self.properties = kwargs.get('properties', None)
        self.measurements = kwargs.get('measurements', None)


class RequestData(MonitorDomain):
    """An instance of Request represents completion of an external request to the application to do work and contains a summary of that request execution and the results.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param version: Required. Schema version.
    :type version: int
    :param id: Required. Identifier of a request call instance. Used for correlation between
     request and other telemetry items.
    :type id: str
    :param name: Name of the request. Represents code path taken to process request. Low
     cardinality value to allow better grouping of requests. For HTTP requests it represents the
     HTTP method and URL path template like 'GET /values/{id}'.
    :type name: str
    :param duration: Required. Request duration in format: DD.HH:MM:SS.MMMMMM. Must be less than
     1000 days.
    :type duration: str
    :param success: Required. Indication of successful or unsuccessful call.
    :type success: bool
    :param response_code: Required. Result of a request execution. HTTP status code for HTTP
     requests.
    :type response_code: str
    :param source: Source of the request. Examples are the instrumentation key of the caller or the
     ip address of the caller.
    :type source: str
    :param url: Request URL with all query string parameters.
    :type url: str
    :param properties: Collection of custom properties.
    :type properties: dict[str, str]
    :param measurements: Collection of custom measurements.
    :type measurements: dict[str, float]
    """

    _validation = {
        'version': {'required': True},
        'id': {'required': True, 'max_length': 512, 'min_length': 0},
        'name': {'max_length': 1024, 'min_length': 0},
        'duration': {'required': True},
        'success': {'required': True},
        'response_code': {'required': True, 'max_length': 1024, 'min_length': 0},
        'source': {'max_length': 1024, 'min_length': 0},
        'url': {'max_length': 2048, 'min_length': 0},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'version': {'key': 'ver', 'type': 'int'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'duration': {'key': 'duration', 'type': 'str'},
        'success': {'key': 'success', 'type': 'bool'},
        'response_code': {'key': 'responseCode', 'type': 'str'},
        'source': {'key': 'source', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'properties': {'key': 'properties', 'type': '{str}'},
        'measurements': {'key': 'measurements', 'type': '{float}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RequestData, self).__init__(**kwargs)
        self.id = kwargs['id']
        self.name = kwargs.get('name', None)
        self.duration = kwargs['duration']
        self.success = kwargs.get('success', True)
        self.response_code = kwargs['response_code']
        self.source = kwargs.get('source', None)
        self.url = kwargs.get('url', None)
        self.properties = kwargs.get('properties', None)
        self.measurements = kwargs.get('measurements', None)


class StackFrame(msrest.serialization.Model):
    """Stack frame information.

    All required parameters must be populated in order to send to Azure.

    :param level: Required.
    :type level: int
    :param method: Required. Method name.
    :type method: str
    :param assembly: Name of the assembly (dll, jar, etc.) containing this function.
    :type assembly: str
    :param file_name: File name or URL of the method implementation.
    :type file_name: str
    :param line: Line number of the code implementation.
    :type line: int
    """

    _validation = {
        'level': {'required': True},
        'method': {'required': True, 'max_length': 1024, 'min_length': 0},
        'assembly': {'max_length': 1024, 'min_length': 0},
        'file_name': {'max_length': 1024, 'min_length': 0},
    }

    _attribute_map = {
        'level': {'key': 'level', 'type': 'int'},
        'method': {'key': 'method', 'type': 'str'},
        'assembly': {'key': 'assembly', 'type': 'str'},
        'file_name': {'key': 'fileName', 'type': 'str'},
        'line': {'key': 'line', 'type': 'int'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(StackFrame, self).__init__(**kwargs)
        self.level = kwargs['level']
        self.method = kwargs['method']
        self.assembly = kwargs.get('assembly', None)
        self.file_name = kwargs.get('file_name', None)
        self.line = kwargs.get('line', None)


class TelemetryErrorDetails(msrest.serialization.Model):
    """The error details.

    :param index: The index in the original payload of the item.
    :type index: int
    :param status_code: The item specific `HTTP Response status code <#Response Status Codes>`_.
    :type status_code: int
    :param message: The error message.
    :type message: str
    """

    _attribute_map = {
        'index': {'key': 'index', 'type': 'int'},
        'status_code': {'key': 'statusCode', 'type': 'int'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TelemetryErrorDetails, self).__init__(**kwargs)
        self.index = kwargs.get('index', None)
        self.status_code = kwargs.get('status_code', None)
        self.message = kwargs.get('message', None)


class TelemetryEventData(MonitorDomain):
    """Instances of Event represent structured event records that can be grouped and searched by their properties. Event data item also creates a metric of event count by name.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param version: Required. Schema version.
    :type version: int
    :param name: Required. Event name. Keep it low cardinality to allow proper grouping and useful
     metrics.
    :type name: str
    :param properties: Collection of custom properties.
    :type properties: dict[str, str]
    :param measurements: Collection of custom measurements.
    :type measurements: dict[str, float]
    """

    _validation = {
        'version': {'required': True},
        'name': {'required': True, 'max_length': 512, 'min_length': 0},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'version': {'key': 'ver', 'type': 'int'},
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': '{str}'},
        'measurements': {'key': 'measurements', 'type': '{float}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TelemetryEventData, self).__init__(**kwargs)
        self.name = kwargs['name']
        self.properties = kwargs.get('properties', None)
        self.measurements = kwargs.get('measurements', None)


class TelemetryExceptionData(MonitorDomain):
    """An instance of Exception represents a handled or unhandled exception that occurred during execution of the monitored application.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are deserialized to this
     collection.
    :type additional_properties: dict[str, object]
    :param version: Required. Schema version.
    :type version: int
    :param exceptions: Required. Exception chain - list of inner exceptions.
    :type exceptions: list[~azure_monitor_client.models.TelemetryExceptionDetails]
    :param severity_level: Severity level. Mostly used to indicate exception severity level when it
     is reported by logging library. Possible values include: "Verbose", "Information", "Warning",
     "Error", "Critical".
    :type severity_level: str or ~azure_monitor_client.models.SeverityLevel
    :param problem_id: Identifier of where the exception was thrown in code. Used for exceptions
     grouping. Typically a combination of exception type and a function from the call stack.
    :type problem_id: str
    :param properties: Collection of custom properties.
    :type properties: dict[str, str]
    :param measurements: Collection of custom measurements.
    :type measurements: dict[str, float]
    """

    _validation = {
        'version': {'required': True},
        'exceptions': {'required': True},
        'problem_id': {'max_length': 1024, 'min_length': 0},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'version': {'key': 'ver', 'type': 'int'},
        'exceptions': {'key': 'exceptions', 'type': '[TelemetryExceptionDetails]'},
        'severity_level': {'key': 'severityLevel', 'type': 'str'},
        'problem_id': {'key': 'problemId', 'type': 'str'},
        'properties': {'key': 'properties', 'type': '{str}'},
        'measurements': {'key': 'measurements', 'type': '{float}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TelemetryExceptionData, self).__init__(**kwargs)
        self.exceptions = kwargs['exceptions']
        self.severity_level = kwargs.get('severity_level', None)
        self.problem_id = kwargs.get('problem_id', None)
        self.properties = kwargs.get('properties', None)
        self.measurements = kwargs.get('measurements', None)


class TelemetryExceptionDetails(msrest.serialization.Model):
    """Exception details of the exception in a chain.

    All required parameters must be populated in order to send to Azure.

    :param id: In case exception is nested (outer exception contains inner one), the id and outerId
     properties are used to represent the nesting.
    :type id: int
    :param outer_id: The value of outerId is a reference to an element in ExceptionDetails that
     represents the outer exception.
    :type outer_id: int
    :param type_name: Exception type name.
    :type type_name: str
    :param message: Required. Exception message.
    :type message: str
    :param has_full_stack: Indicates if full exception stack is provided in the exception. The
     stack may be trimmed, such as in the case of a StackOverflow exception.
    :type has_full_stack: bool
    :param stack: Text describing the stack. Either stack or parsedStack should have a value.
    :type stack: str
    :param parsed_stack: List of stack frames. Either stack or parsedStack should have a value.
    :type parsed_stack: list[~azure_monitor_client.models.StackFrame]
    """

    _validation = {
        'type_name': {'max_length': 1024, 'min_length': 0},
        'message': {'required': True, 'max_length': 32768, 'min_length': 0},
        'stack': {'max_length': 32768, 'min_length': 0},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'int'},
        'outer_id': {'key': 'outerId', 'type': 'int'},
        'type_name': {'key': 'typeName', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'has_full_stack': {'key': 'hasFullStack', 'type': 'bool'},
        'stack': {'key': 'stack', 'type': 'str'},
        'parsed_stack': {'key': 'parsedStack', 'type': '[StackFrame]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TelemetryExceptionDetails, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.outer_id = kwargs.get('outer_id', None)
        self.type_name = kwargs.get('type_name', None)
        self.message = kwargs['message']
        self.has_full_stack = kwargs.get('has_full_stack', True)
        self.stack = kwargs.get('stack', None)
        self.parsed_stack = kwargs.get('parsed_stack', None)


class TelemetryItem(msrest.serialization.Model):
    """System variables for a telemetry item.

    All required parameters must be populated in order to send to Azure.

    :param version: Envelope version. For internal use only. By assigning this the default, it will
     not be serialized within the payload unless changed to a value other than #1.
    :type version: int
    :param name: Required. Type name of telemetry data item.
    :type name: str
    :param time: Required. Event date time when telemetry item was created. This is the wall clock
     time on the client when the event was generated. There is no guarantee that the client's time
     is accurate. This field must be formatted in UTC ISO 8601 format, with a trailing 'Z'
     character, as described publicly on https://en.wikipedia.org/wiki/ISO_8601#UTC. Note: the
     number of decimal seconds digits provided are variable (and unspecified). Consumers should
     handle this, i.e. managed code consumers should not use format 'O' for parsing as it specifies
     a fixed length. Example: 2009-06-15T13:45:30.0000000Z.
    :type time: ~datetime.datetime
    :param sample_rate: Sampling rate used in application. This telemetry item represents 1 /
     sampleRate actual telemetry items.
    :type sample_rate: float
    :param sequence: Sequence field used to track absolute order of uploaded events.
    :type sequence: str
    :param instrumentation_key: The instrumentation key of the Application Insights resource.
    :type instrumentation_key: str
    :param tags: A set of tags. Key/value collection of context properties. See ContextTagKeys for
     information on available properties.
    :type tags: dict[str, str]
    :param data: Telemetry data item.
    :type data: ~azure_monitor_client.models.MonitorBase
    """

    _validation = {
        'name': {'required': True},
        'time': {'required': True},
        'sequence': {'max_length': 64, 'min_length': 0},
    }

    _attribute_map = {
        'version': {'key': 'ver', 'type': 'int'},
        'name': {'key': 'name', 'type': 'str'},
        'time': {'key': 'time', 'type': 'iso-8601'},
        'sample_rate': {'key': 'sampleRate', 'type': 'float'},
        'sequence': {'key': 'seq', 'type': 'str'},
        'instrumentation_key': {'key': 'iKey', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'data': {'key': 'data', 'type': 'MonitorBase'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TelemetryItem, self).__init__(**kwargs)
        self.version = kwargs.get('version', 1)
        self.name = kwargs['name']
        self.time = kwargs['time']
        self.sample_rate = kwargs.get('sample_rate', 100)
        self.sequence = kwargs.get('sequence', None)
        self.instrumentation_key = kwargs.get('instrumentation_key', None)
        self.tags = kwargs.get('tags', None)
        self.data = kwargs.get('data', None)


class TrackResponse(msrest.serialization.Model):
    """Response containing the status of each telemetry item.

    :param items_received: The number of items received.
    :type items_received: int
    :param items_accepted: The number of items accepted.
    :type items_accepted: int
    :param errors: An array of error detail objects.
    :type errors: list[~azure_monitor_client.models.TelemetryErrorDetails]
    """

    _attribute_map = {
        'items_received': {'key': 'itemsReceived', 'type': 'int'},
        'items_accepted': {'key': 'itemsAccepted', 'type': 'int'},
        'errors': {'key': 'errors', 'type': '[TelemetryErrorDetails]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TrackResponse, self).__init__(**kwargs)
        self.items_received = kwargs.get('items_received', None)
        self.items_accepted = kwargs.get('items_accepted', None)
        self.errors = kwargs.get('errors', None)
