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

from enum import Enum


class IngressQoSLevel(str, Enum):

    bronze = "Bronze"


class HealthState(str, Enum):

    invalid = "Invalid"  #: Indicates an invalid health state. All Service Fabric enumerations have the invalid type. The value is zero.
    ok = "Ok"  #: Indicates the health state is okay. The value is 1.
    warning = "Warning"  #: Indicates the health state is at a warning level. The value is 2.
    error = "Error"  #: Indicates the health state is at an error level. Error health state should be investigated, as they can impact the correct functionality of the cluster. The value is 3.
    unknown = "Unknown"  #: Indicates an unknown health status. The value is 65535.


class ServiceResourceStatus(str, Enum):

    unknown = "Unknown"
    active = "Active"
    upgrading = "Upgrading"
    deleting = "Deleting"
    creating = "Creating"
    failed = "Failed"


class ApplicationResourceStatus(str, Enum):

    invalid = "Invalid"
    ready = "Ready"
    upgrading = "Upgrading"
    creating = "Creating"
    deleting = "Deleting"
    failed = "Failed"


class OperatingSystemTypes(str, Enum):

    linux = "Linux"
    windows = "Windows"


class DiagnosticsSinkKind(str, Enum):

    invalid = "Invalid"  #: Indicates an invalid sink kind. All Service Fabric enumerations have the invalid type.
    azure_internal_monitoring_pipeline = "AzureInternalMonitoringPipeline"  #: Diagnostics settings for Geneva.
