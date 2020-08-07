# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class ErrorResponse(msrest.serialization.Model):
    """Describes the format of Error response.

    :param code: Error code.
    :type code: str
    :param message: Error message indicating why the operation failed.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)


class LocalizableString(msrest.serialization.Model):
    """The localizable string class.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. the invariant value.
    :type value: str
    :param localized_value: the locale specific value.
    :type localized_value: str
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': 'str'},
        'localized_value': {'key': 'localizedValue', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LocalizableString, self).__init__(**kwargs)
        self.value = kwargs['value']
        self.localized_value = kwargs.get('localized_value', None)


class MetadataValue(msrest.serialization.Model):
    """Represents a metric metadata value.

    :param name: the name of the metadata.
    :type name: ~$(python-base-namespace).v2018_01_01.models.LocalizableString
    :param value: the value of the metadata.
    :type value: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'LocalizableString'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MetadataValue, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.value = kwargs.get('value', None)


class Metric(msrest.serialization.Model):
    """The result data of a query.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. the metric Id.
    :type id: str
    :param type: Required. the resource type of the metric resource.
    :type type: str
    :param name: Required. the name and the display name of the metric, i.e. it is localizable
     string.
    :type name: ~$(python-base-namespace).v2018_01_01.models.LocalizableString
    :param unit: Required. the unit of the metric. Possible values include: "Count", "Bytes",
     "Seconds", "CountPerSecond", "BytesPerSecond", "Percent", "MilliSeconds", "ByteSeconds",
     "Unspecified", "Cores", "MilliCores", "NanoCores", "BitsPerSecond".
    :type unit: str or ~$(python-base-namespace).v2018_01_01.models.Unit
    :param timeseries: Required. the time series returned when a data query is performed.
    :type timeseries: list[~$(python-base-namespace).v2018_01_01.models.TimeSeriesElement]
    """

    _validation = {
        'id': {'required': True},
        'type': {'required': True},
        'name': {'required': True},
        'unit': {'required': True},
        'timeseries': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'LocalizableString'},
        'unit': {'key': 'unit', 'type': 'str'},
        'timeseries': {'key': 'timeseries', 'type': '[TimeSeriesElement]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Metric, self).__init__(**kwargs)
        self.id = kwargs['id']
        self.type = kwargs['type']
        self.name = kwargs['name']
        self.unit = kwargs['unit']
        self.timeseries = kwargs['timeseries']


class MetricAvailability(msrest.serialization.Model):
    """Metric availability specifies the time grain (aggregation interval or frequency) and the retention period for that time grain.

    :param time_grain: the time grain specifies the aggregation interval for the metric. Expressed
     as a duration 'PT1M', 'P1D', etc.
    :type time_grain: ~datetime.timedelta
    :param retention: the retention period for the metric at the specified timegrain.  Expressed as
     a duration 'PT1M', 'P1D', etc.
    :type retention: ~datetime.timedelta
    """

    _attribute_map = {
        'time_grain': {'key': 'timeGrain', 'type': 'duration'},
        'retention': {'key': 'retention', 'type': 'duration'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MetricAvailability, self).__init__(**kwargs)
        self.time_grain = kwargs.get('time_grain', None)
        self.retention = kwargs.get('retention', None)


class MetricDefinition(msrest.serialization.Model):
    """Metric definition class specifies the metadata for a metric.

    :param is_dimension_required: Flag to indicate whether the dimension is required.
    :type is_dimension_required: bool
    :param resource_id: the resource identifier of the resource that emitted the metric.
    :type resource_id: str
    :param namespace: the namespace the metric belongs to.
    :type namespace: str
    :param name: the name and the display name of the metric, i.e. it is a localizable string.
    :type name: ~$(python-base-namespace).v2018_01_01.models.LocalizableString
    :param unit: the unit of the metric. Possible values include: "Count", "Bytes", "Seconds",
     "CountPerSecond", "BytesPerSecond", "Percent", "MilliSeconds", "ByteSeconds", "Unspecified",
     "Cores", "MilliCores", "NanoCores", "BitsPerSecond".
    :type unit: str or ~$(python-base-namespace).v2018_01_01.models.Unit
    :param primary_aggregation_type: the primary aggregation type value defining how to use the
     values for display. Possible values include: "None", "Average", "Count", "Minimum", "Maximum",
     "Total".
    :type primary_aggregation_type: str or ~$(python-base-
     namespace).v2018_01_01.models.AggregationType
    :param supported_aggregation_types: the collection of what aggregation types are supported.
    :type supported_aggregation_types: list[str or ~$(python-base-
     namespace).v2018_01_01.models.AggregationType]
    :param metric_availabilities: the collection of what aggregation intervals are available to be
     queried.
    :type metric_availabilities: list[~$(python-base-
     namespace).v2018_01_01.models.MetricAvailability]
    :param id: the resource identifier of the metric definition.
    :type id: str
    :param dimensions: the name and the display name of the dimension, i.e. it is a localizable
     string.
    :type dimensions: list[~$(python-base-namespace).v2018_01_01.models.LocalizableString]
    """

    _attribute_map = {
        'is_dimension_required': {'key': 'isDimensionRequired', 'type': 'bool'},
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'namespace': {'key': 'namespace', 'type': 'str'},
        'name': {'key': 'name', 'type': 'LocalizableString'},
        'unit': {'key': 'unit', 'type': 'str'},
        'primary_aggregation_type': {'key': 'primaryAggregationType', 'type': 'str'},
        'supported_aggregation_types': {'key': 'supportedAggregationTypes', 'type': '[str]'},
        'metric_availabilities': {'key': 'metricAvailabilities', 'type': '[MetricAvailability]'},
        'id': {'key': 'id', 'type': 'str'},
        'dimensions': {'key': 'dimensions', 'type': '[LocalizableString]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MetricDefinition, self).__init__(**kwargs)
        self.is_dimension_required = kwargs.get('is_dimension_required', None)
        self.resource_id = kwargs.get('resource_id', None)
        self.namespace = kwargs.get('namespace', None)
        self.name = kwargs.get('name', None)
        self.unit = kwargs.get('unit', None)
        self.primary_aggregation_type = kwargs.get('primary_aggregation_type', None)
        self.supported_aggregation_types = kwargs.get('supported_aggregation_types', None)
        self.metric_availabilities = kwargs.get('metric_availabilities', None)
        self.id = kwargs.get('id', None)
        self.dimensions = kwargs.get('dimensions', None)


class MetricDefinitionCollection(msrest.serialization.Model):
    """Represents collection of metric definitions.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. the values for the metric definitions.
    :type value: list[~$(python-base-namespace).v2018_01_01.models.MetricDefinition]
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[MetricDefinition]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MetricDefinitionCollection, self).__init__(**kwargs)
        self.value = kwargs['value']


class MetricValue(msrest.serialization.Model):
    """Represents a metric value.

    All required parameters must be populated in order to send to Azure.

    :param time_stamp: Required. the timestamp for the metric value in ISO 8601 format.
    :type time_stamp: ~datetime.datetime
    :param average: the average value in the time range.
    :type average: float
    :param minimum: the least value in the time range.
    :type minimum: float
    :param maximum: the greatest value in the time range.
    :type maximum: float
    :param total: the sum of all of the values in the time range.
    :type total: float
    :param count: the number of samples in the time range. Can be used to determine the number of
     values that contributed to the average value.
    :type count: float
    """

    _validation = {
        'time_stamp': {'required': True},
    }

    _attribute_map = {
        'time_stamp': {'key': 'timeStamp', 'type': 'iso-8601'},
        'average': {'key': 'average', 'type': 'float'},
        'minimum': {'key': 'minimum', 'type': 'float'},
        'maximum': {'key': 'maximum', 'type': 'float'},
        'total': {'key': 'total', 'type': 'float'},
        'count': {'key': 'count', 'type': 'float'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MetricValue, self).__init__(**kwargs)
        self.time_stamp = kwargs['time_stamp']
        self.average = kwargs.get('average', None)
        self.minimum = kwargs.get('minimum', None)
        self.maximum = kwargs.get('maximum', None)
        self.total = kwargs.get('total', None)
        self.count = kwargs.get('count', None)


class Response(msrest.serialization.Model):
    """The response to a metrics query.

    All required parameters must be populated in order to send to Azure.

    :param cost: The integer value representing the cost of the query, for data case.
    :type cost: int
    :param timespan: Required. The timespan for which the data was retrieved. Its value consists of
     two datetimes concatenated, separated by '/'.  This may be adjusted in the future and returned
     back from what was originally requested.
    :type timespan: str
    :param interval: The interval (window size) for which the metric data was returned in.  This
     may be adjusted in the future and returned back from what was originally requested.  This is
     not present if a metadata request was made.
    :type interval: ~datetime.timedelta
    :param namespace: The namespace of the metrics been queried.
    :type namespace: str
    :param resourceregion: The region of the resource been queried for metrics.
    :type resourceregion: str
    :param value: Required. the value of the collection.
    :type value: list[~$(python-base-namespace).v2018_01_01.models.Metric]
    """

    _validation = {
        'cost': {'minimum': 0},
        'timespan': {'required': True},
        'value': {'required': True},
    }

    _attribute_map = {
        'cost': {'key': 'cost', 'type': 'int'},
        'timespan': {'key': 'timespan', 'type': 'str'},
        'interval': {'key': 'interval', 'type': 'duration'},
        'namespace': {'key': 'namespace', 'type': 'str'},
        'resourceregion': {'key': 'resourceregion', 'type': 'str'},
        'value': {'key': 'value', 'type': '[Metric]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Response, self).__init__(**kwargs)
        self.cost = kwargs.get('cost', None)
        self.timespan = kwargs['timespan']
        self.interval = kwargs.get('interval', None)
        self.namespace = kwargs.get('namespace', None)
        self.resourceregion = kwargs.get('resourceregion', None)
        self.value = kwargs['value']


class TimeSeriesElement(msrest.serialization.Model):
    """A time series result type. The discriminator value is always TimeSeries in this case.

    :param metadatavalues: the metadata values returned if $filter was specified in the call.
    :type metadatavalues: list[~$(python-base-namespace).v2018_01_01.models.MetadataValue]
    :param data: An array of data points representing the metric values.  This is only returned if
     a result type of data is specified.
    :type data: list[~$(python-base-namespace).v2018_01_01.models.MetricValue]
    """

    _attribute_map = {
        'metadatavalues': {'key': 'metadatavalues', 'type': '[MetadataValue]'},
        'data': {'key': 'data', 'type': '[MetricValue]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TimeSeriesElement, self).__init__(**kwargs)
        self.metadatavalues = kwargs.get('metadatavalues', None)
        self.data = kwargs.get('data', None)
