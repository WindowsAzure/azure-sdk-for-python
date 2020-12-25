# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import ErrorResponse
    from ._models_py3 import LocalizableString
    from ._models_py3 import MetadataValue
    from ._models_py3 import Metric
    from ._models_py3 import MetricAvailability
    from ._models_py3 import MetricDefinition
    from ._models_py3 import MetricDefinitionCollection
    from ._models_py3 import MetricValue
    from ._models_py3 import Response
    from ._models_py3 import TimeSeriesElement
except (SyntaxError, ImportError):
    from ._models import ErrorResponse  # type: ignore
    from ._models import LocalizableString  # type: ignore
    from ._models import MetadataValue  # type: ignore
    from ._models import Metric  # type: ignore
    from ._models import MetricAvailability  # type: ignore
    from ._models import MetricDefinition  # type: ignore
    from ._models import MetricDefinitionCollection  # type: ignore
    from ._models import MetricValue  # type: ignore
    from ._models import Response  # type: ignore
    from ._models import TimeSeriesElement  # type: ignore

from ._monitor_management_client_enums import (
    AggregationType,
    ResultType,
    Unit,
)

__all__ = [
    'ErrorResponse',
    'LocalizableString',
    'MetadataValue',
    'Metric',
    'MetricAvailability',
    'MetricDefinition',
    'MetricDefinitionCollection',
    'MetricValue',
    'Response',
    'TimeSeriesElement',
    'AggregationType',
    'ResultType',
    'Unit',
]
