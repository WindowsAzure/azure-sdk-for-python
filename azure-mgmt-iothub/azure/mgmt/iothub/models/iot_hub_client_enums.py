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


class AccessRights(Enum):

    registry_read = "RegistryRead"
    registry_write = "RegistryWrite"
    service_connect = "ServiceConnect"
    device_connect = "DeviceConnect"
    registry_read_registry_write = "RegistryRead, RegistryWrite"
    registry_read_service_connect = "RegistryRead, ServiceConnect"
    registry_read_device_connect = "RegistryRead, DeviceConnect"
    registry_write_service_connect = "RegistryWrite, ServiceConnect"
    registry_write_device_connect = "RegistryWrite, DeviceConnect"
    service_connect_device_connect = "ServiceConnect, DeviceConnect"
    registry_read_registry_write_service_connect = "RegistryRead, RegistryWrite, ServiceConnect"
    registry_read_registry_write_device_connect = "RegistryRead, RegistryWrite, DeviceConnect"
    registry_read_service_connect_device_connect = "RegistryRead, ServiceConnect, DeviceConnect"
    registry_write_service_connect_device_connect = "RegistryWrite, ServiceConnect, DeviceConnect"
    registry_read_registry_write_service_connect_device_connect = "RegistryRead, RegistryWrite, ServiceConnect, DeviceConnect"


class IpFilterActionType(Enum):

    accept = "Accept"
    reject = "Reject"


class OperationMonitoringLevel(Enum):

    none = "None"
    error = "Error"
    information = "Information"
    error_information = "Error, Information"


class Capabilities(Enum):

    none = "None"
    device_management = "DeviceManagement"


class IotHubSku(Enum):

    f1 = "F1"
    s1 = "S1"
    s2 = "S2"
    s3 = "S3"


class IotHubSkuTier(Enum):

    free = "Free"
    standard = "Standard"


class JobType(Enum):

    unknown = "unknown"
    export = "export"
    import_enum = "import"
    backup = "backup"
    read_device_properties = "readDeviceProperties"
    write_device_properties = "writeDeviceProperties"
    update_device_configuration = "updateDeviceConfiguration"
    reboot_device = "rebootDevice"
    factory_reset_device = "factoryResetDevice"
    firmware_update = "firmwareUpdate"


class JobStatus(Enum):

    unknown = "unknown"
    enqueued = "enqueued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class IotHubScaleType(Enum):

    automatic = "Automatic"
    manual = "Manual"
    none = "None"


class IotHubNameUnavailabilityReason(Enum):

    invalid = "Invalid"
    already_exists = "AlreadyExists"
