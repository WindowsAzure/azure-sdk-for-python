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
    from ._models_py3 import Disk
    from ._models_py3 import Display
    from ._models_py3 import ErrorResponse, ErrorResponseException
    from ._models_py3 import HanaInstance
    from ._models_py3 import HardwareProfile
    from ._models_py3 import IpAddress
    from ._models_py3 import MonitoringDetails
    from ._models_py3 import NetworkProfile
    from ._models_py3 import Operation
    from ._models_py3 import OSProfile
    from ._models_py3 import Resource
    from ._models_py3 import SapMonitor
    from ._models_py3 import StorageProfile
    from ._models_py3 import Tags
except (SyntaxError, ImportError):
    from ._models import Disk
    from ._models import Display
    from ._models import ErrorResponse, ErrorResponseException
    from ._models import HanaInstance
    from ._models import HardwareProfile
    from ._models import IpAddress
    from ._models import MonitoringDetails
    from ._models import NetworkProfile
    from ._models import Operation
    from ._models import OSProfile
    from ._models import Resource
    from ._models import SapMonitor
    from ._models import StorageProfile
    from ._models import Tags
from ._paged_models import HanaInstancePaged
from ._paged_models import OperationPaged
from ._paged_models import SapMonitorPaged
from ._hana_management_client_enums import (
    HanaHardwareTypeNamesEnum,
    HanaInstanceSizeNamesEnum,
    HanaInstancePowerStateEnum,
    HanaProvisioningStatesEnum,
)

__all__ = [
    'Disk',
    'Display',
    'ErrorResponse', 'ErrorResponseException',
    'HanaInstance',
    'HardwareProfile',
    'IpAddress',
    'MonitoringDetails',
    'NetworkProfile',
    'Operation',
    'OSProfile',
    'Resource',
    'SapMonitor',
    'StorageProfile',
    'Tags',
    'OperationPaged',
    'HanaInstancePaged',
    'SapMonitorPaged',
    'HanaHardwareTypeNamesEnum',
    'HanaInstanceSizeNamesEnum',
    'HanaInstancePowerStateEnum',
    'HanaProvisioningStatesEnum',
]
