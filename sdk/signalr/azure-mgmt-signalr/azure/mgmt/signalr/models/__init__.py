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

try:
    from .operation_display_py3 import OperationDisplay
    from .dimension_py3 import Dimension
    from .metric_specification_py3 import MetricSpecification
    from .service_specification_py3 import ServiceSpecification
    from .operation_properties_py3 import OperationProperties
    from .operation_py3 import Operation
    from .name_availability_parameters_py3 import NameAvailabilityParameters
    from .name_availability_py3 import NameAvailability
    from .resource_sku_py3 import ResourceSku
    from .signal_rresource_py3 import SignalRResource
    from .tracked_resource_py3 import TrackedResource
    from .resource_py3 import Resource
    from .signal_rfeature_py3 import SignalRFeature
    from .signal_rcors_settings_py3 import SignalRCorsSettings
    from .signal_rcreate_or_update_properties_py3 import SignalRCreateOrUpdateProperties
    from .signal_rkeys_py3 import SignalRKeys
    from .regenerate_key_parameters_py3 import RegenerateKeyParameters
    from .signal_rcreate_parameters_py3 import SignalRCreateParameters
    from .signal_rupdate_parameters_py3 import SignalRUpdateParameters
    from .signal_rusage_name_py3 import SignalRUsageName
    from .signal_rusage_py3 import SignalRUsage
except (SyntaxError, ImportError):
    from .operation_display import OperationDisplay
    from .dimension import Dimension
    from .metric_specification import MetricSpecification
    from .service_specification import ServiceSpecification
    from .operation_properties import OperationProperties
    from .operation import Operation
    from .name_availability_parameters import NameAvailabilityParameters
    from .name_availability import NameAvailability
    from .resource_sku import ResourceSku
    from .signal_rresource import SignalRResource
    from .tracked_resource import TrackedResource
    from .resource import Resource
    from .signal_rfeature import SignalRFeature
    from .signal_rcors_settings import SignalRCorsSettings
    from .signal_rcreate_or_update_properties import SignalRCreateOrUpdateProperties
    from .signal_rkeys import SignalRKeys
    from .regenerate_key_parameters import RegenerateKeyParameters
    from .signal_rcreate_parameters import SignalRCreateParameters
    from .signal_rupdate_parameters import SignalRUpdateParameters
    from .signal_rusage_name import SignalRUsageName
    from .signal_rusage import SignalRUsage
from .operation_paged import OperationPaged
from .signal_rresource_paged import SignalRResourcePaged
from .signal_rusage_paged import SignalRUsagePaged
from .signal_rmanagement_client_enums import (
    SignalRSkuTier,
    ProvisioningState,
    KeyType,
)

__all__ = [
    'OperationDisplay',
    'Dimension',
    'MetricSpecification',
    'ServiceSpecification',
    'OperationProperties',
    'Operation',
    'NameAvailabilityParameters',
    'NameAvailability',
    'ResourceSku',
    'SignalRResource',
    'TrackedResource',
    'Resource',
    'SignalRFeature',
    'SignalRCorsSettings',
    'SignalRCreateOrUpdateProperties',
    'SignalRKeys',
    'RegenerateKeyParameters',
    'SignalRCreateParameters',
    'SignalRUpdateParameters',
    'SignalRUsageName',
    'SignalRUsage',
    'OperationPaged',
    'SignalRResourcePaged',
    'SignalRUsagePaged',
    'SignalRSkuTier',
    'ProvisioningState',
    'KeyType',
]
