# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
# Code generated by Microsoft (R) AutoRest Code Generator.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AccessCondition
    from ._models_py3 import Compatibility
    from ._models_py3 import Deployment
    from ._models_py3 import DeploymentDeviceState
    from ._models_py3 import DeploymentDeviceStatesFilter
    from ._models_py3 import DeploymentFilter
    from ._models_py3 import DeploymentStatus
    from ._models_py3 import Device
    from ._models_py3 import DeviceClass
    from ._models_py3 import DeviceFilter
    from ._models_py3 import DeviceTag
    from ._models_py3 import Error
    from ._models_py3 import File
    from ._models_py3 import FileImportMetadata
    from ._models_py3 import Group
    from ._models_py3 import GroupBestUpdatesFilter
    from ._models_py3 import ImportManifestMetadata
    from ._models_py3 import ImportUpdateInput
    from ._models_py3 import InnerError
    from ._models_py3 import Operation
    from ._models_py3 import OperationFilter
    from ._models_py3 import PageableListOfDeploymentDeviceStates
    from ._models_py3 import PageableListOfDeployments
    from ._models_py3 import PageableListOfDeviceClasses
    from ._models_py3 import PageableListOfDeviceTags
    from ._models_py3 import PageableListOfDevices
    from ._models_py3 import PageableListOfGroups
    from ._models_py3 import PageableListOfOperations
    from ._models_py3 import PageableListOfStrings
    from ._models_py3 import PageableListOfUpdatableDevices
    from ._models_py3 import PageableListOfUpdateIds
    from ._models_py3 import UpdatableDevices
    from ._models_py3 import Update
    from ._models_py3 import UpdateCompliance
    from ._models_py3 import UpdateId
except (SyntaxError, ImportError):
    from ._models import AccessCondition  # type: ignore
    from ._models import Compatibility  # type: ignore
    from ._models import Deployment  # type: ignore
    from ._models import DeploymentDeviceState  # type: ignore
    from ._models import DeploymentDeviceStatesFilter  # type: ignore
    from ._models import DeploymentFilter  # type: ignore
    from ._models import DeploymentStatus  # type: ignore
    from ._models import Device  # type: ignore
    from ._models import DeviceClass  # type: ignore
    from ._models import DeviceFilter  # type: ignore
    from ._models import DeviceTag  # type: ignore
    from ._models import Error  # type: ignore
    from ._models import File  # type: ignore
    from ._models import FileImportMetadata  # type: ignore
    from ._models import Group  # type: ignore
    from ._models import GroupBestUpdatesFilter  # type: ignore
    from ._models import ImportManifestMetadata  # type: ignore
    from ._models import ImportUpdateInput  # type: ignore
    from ._models import InnerError  # type: ignore
    from ._models import Operation  # type: ignore
    from ._models import OperationFilter  # type: ignore
    from ._models import PageableListOfDeploymentDeviceStates  # type: ignore
    from ._models import PageableListOfDeployments  # type: ignore
    from ._models import PageableListOfDeviceClasses  # type: ignore
    from ._models import PageableListOfDeviceTags  # type: ignore
    from ._models import PageableListOfDevices  # type: ignore
    from ._models import PageableListOfGroups  # type: ignore
    from ._models import PageableListOfOperations  # type: ignore
    from ._models import PageableListOfStrings  # type: ignore
    from ._models import PageableListOfUpdatableDevices  # type: ignore
    from ._models import PageableListOfUpdateIds  # type: ignore
    from ._models import UpdatableDevices  # type: ignore
    from ._models import Update  # type: ignore
    from ._models import UpdateCompliance  # type: ignore
    from ._models import UpdateId  # type: ignore

from ._device_update_client_enums import (
    DeploymentState,
    DeploymentType,
    DeviceDeploymentState,
    DeviceGroupType,
    DeviceState,
    GroupType,
    OperationFilterStatus,
    OperationStatus,
)

__all__ = [
    'AccessCondition',
    'Compatibility',
    'Deployment',
    'DeploymentDeviceState',
    'DeploymentDeviceStatesFilter',
    'DeploymentFilter',
    'DeploymentStatus',
    'Device',
    'DeviceClass',
    'DeviceFilter',
    'DeviceTag',
    'Error',
    'File',
    'FileImportMetadata',
    'Group',
    'GroupBestUpdatesFilter',
    'ImportManifestMetadata',
    'ImportUpdateInput',
    'InnerError',
    'Operation',
    'OperationFilter',
    'PageableListOfDeploymentDeviceStates',
    'PageableListOfDeployments',
    'PageableListOfDeviceClasses',
    'PageableListOfDeviceTags',
    'PageableListOfDevices',
    'PageableListOfGroups',
    'PageableListOfOperations',
    'PageableListOfStrings',
    'PageableListOfUpdatableDevices',
    'PageableListOfUpdateIds',
    'UpdatableDevices',
    'Update',
    'UpdateCompliance',
    'UpdateId',
    'DeploymentState',
    'DeploymentType',
    'DeviceDeploymentState',
    'DeviceGroupType',
    'DeviceState',
    'GroupType',
    'OperationFilterStatus',
    'OperationStatus',
]
