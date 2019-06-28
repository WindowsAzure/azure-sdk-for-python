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


class Baseline(Model):
    """The baseline values for a single sensitivity value.

    All required parameters must be populated in order to send to Azure.

    :param sensitivity: Required. the sensitivity of the baseline. Possible
     values include: 'Low', 'Medium', 'High'
    :type sensitivity: str or
     ~azure.mgmt.monitor.v2017_11_01_preview.models.Sensitivity
    :param low_thresholds: Required. The low thresholds of the baseline.
    :type low_thresholds: list[float]
    :param high_thresholds: Required. The high thresholds of the baseline.
    :type high_thresholds: list[float]
    """

    _validation = {
        'sensitivity': {'required': True},
        'low_thresholds': {'required': True},
        'high_thresholds': {'required': True},
    }

    _attribute_map = {
        'sensitivity': {'key': 'sensitivity', 'type': 'Sensitivity'},
        'low_thresholds': {'key': 'lowThresholds', 'type': '[float]'},
        'high_thresholds': {'key': 'highThresholds', 'type': '[float]'},
    }

    def __init__(self, *, sensitivity, low_thresholds, high_thresholds, **kwargs) -> None:
        super(Baseline, self).__init__(**kwargs)
        self.sensitivity = sensitivity
        self.low_thresholds = low_thresholds
        self.high_thresholds = high_thresholds


class BaselineMetadataValue(Model):
    """Represents a baseline metadata value.

    :param name: the name of the metadata.
    :type name:
     ~azure.mgmt.monitor.v2017_11_01_preview.models.LocalizableString
    :param value: the value of the metadata.
    :type value: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'LocalizableString'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, *, name=None, value: str=None, **kwargs) -> None:
        super(BaselineMetadataValue, self).__init__(**kwargs)
        self.name = name
        self.value = value


class BaselineResponse(Model):
    """The response to a baseline query.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: the metric baseline Id.
    :vartype id: str
    :ivar type: the resource type of the baseline resource.
    :vartype type: str
    :ivar name: the name and the display name of the metric, i.e. it is
     localizable string.
    :vartype name:
     ~azure.mgmt.monitor.v2017_11_01_preview.models.LocalizableString
    :param timespan: The timespan for which the data was retrieved. Its value
     consists of two datetimes concatenated, separated by '/'.  This may be
     adjusted in the future and returned back from what was originally
     requested.
    :type timespan: str
    :param interval: The interval (window size) for which the metric data was
     returned in.  This may be adjusted in the future and returned back from
     what was originally requested.  This is not present if a metadata request
     was made.
    :type interval: timedelta
    :param aggregation: The aggregation type of the metric.
    :type aggregation: str
    :param timestamps: the array of timestamps of the baselines.
    :type timestamps: list[datetime]
    :param baseline: the baseline values for each sensitivity.
    :type baseline:
     list[~azure.mgmt.monitor.v2017_11_01_preview.models.Baseline]
    :param metadata: the baseline metadata values.
    :type metadata:
     list[~azure.mgmt.monitor.v2017_11_01_preview.models.BaselineMetadataValue]
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'LocalizableString'},
        'timespan': {'key': 'properties.timespan', 'type': 'str'},
        'interval': {'key': 'properties.interval', 'type': 'duration'},
        'aggregation': {'key': 'properties.aggregation', 'type': 'str'},
        'timestamps': {'key': 'properties.timestamps', 'type': '[iso-8601]'},
        'baseline': {'key': 'properties.baseline', 'type': '[Baseline]'},
        'metadata': {'key': 'properties.metadata', 'type': '[BaselineMetadataValue]'},
    }

    def __init__(self, *, timespan: str=None, interval=None, aggregation: str=None, timestamps=None, baseline=None, metadata=None, **kwargs) -> None:
        super(BaselineResponse, self).__init__(**kwargs)
        self.id = None
        self.type = None
        self.name = None
        self.timespan = timespan
        self.interval = interval
        self.aggregation = aggregation
        self.timestamps = timestamps
        self.baseline = baseline
        self.metadata = metadata


class CalculateBaselineResponse(Model):
    """The response to a calculate baseline call.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. the resource type of the baseline resource.
    :type type: str
    :param timestamps: the array of timestamps of the baselines.
    :type timestamps: list[datetime]
    :param baseline: Required. the baseline values for each sensitivity.
    :type baseline:
     list[~azure.mgmt.monitor.v2017_11_01_preview.models.Baseline]
    """

    _validation = {
        'type': {'required': True},
        'baseline': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'timestamps': {'key': 'timestamps', 'type': '[iso-8601]'},
        'baseline': {'key': 'baseline', 'type': '[Baseline]'},
    }

    def __init__(self, *, type: str, baseline, timestamps=None, **kwargs) -> None:
        super(CalculateBaselineResponse, self).__init__(**kwargs)
        self.type = type
        self.timestamps = timestamps
        self.baseline = baseline


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class ErrorResponse(Model):
    """Describes the format of Error response.

    :param code: Error code
    :type code: str
    :param message: Error message indicating why the operation failed.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, *, code: str=None, message: str=None, **kwargs) -> None:
        super(ErrorResponse, self).__init__(**kwargs)
        self.code = code
        self.message = message


class ErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorResponseException, self).__init__(deserialize, response, 'ErrorResponse', *args)


class LocalizableString(Model):
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

    def __init__(self, *, value: str, localized_value: str=None, **kwargs) -> None:
        super(LocalizableString, self).__init__(**kwargs)
        self.value = value
        self.localized_value = localized_value


class TimeSeriesInformation(Model):
    """The time series info needed for calculating the baseline.

    All required parameters must be populated in order to send to Azure.

    :param sensitivities: Required. the list of sensitivities for calculating
     the baseline.
    :type sensitivities: list[str]
    :param values: Required. The metric values to calculate the baseline.
    :type values: list[float]
    :param timestamps: the array of timestamps of the baselines.
    :type timestamps: list[datetime]
    """

    _validation = {
        'sensitivities': {'required': True},
        'values': {'required': True},
    }

    _attribute_map = {
        'sensitivities': {'key': 'sensitivities', 'type': '[str]'},
        'values': {'key': 'values', 'type': '[float]'},
        'timestamps': {'key': 'timestamps', 'type': '[iso-8601]'},
    }

    def __init__(self, *, sensitivities, values, timestamps=None, **kwargs) -> None:
        super(TimeSeriesInformation, self).__init__(**kwargs)
        self.sensitivities = sensitivities
        self.values = values
        self.timestamps = timestamps
