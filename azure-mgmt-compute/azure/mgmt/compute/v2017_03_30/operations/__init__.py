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
    from .availability_sets_operations_async import AvailabilitySetsOperations
    from .virtual_machine_extension_images_operations_async import VirtualMachineExtensionImagesOperations
    from .virtual_machine_extensions_operations_async import VirtualMachineExtensionsOperations
    from .virtual_machine_images_operations_async import VirtualMachineImagesOperations
    from .usage_operations_async import UsageOperations
    from .virtual_machine_sizes_operations_async import VirtualMachineSizesOperations
    from .images_operations_async import ImagesOperations
    from .resource_skus_operations_async import ResourceSkusOperations
    from .virtual_machines_operations_async import VirtualMachinesOperations
    from .virtual_machine_scale_sets_operations_async import VirtualMachineScaleSetsOperations
    from .virtual_machine_scale_set_extensions_operations_async import VirtualMachineScaleSetExtensionsOperations
    from .virtual_machine_scale_set_rolling_upgrades_operations_async import VirtualMachineScaleSetRollingUpgradesOperations
    from .virtual_machine_scale_set_vms_operations_async import VirtualMachineScaleSetVMsOperations
    from .disks_operations_async import DisksOperations
    from .snapshots_operations_async import SnapshotsOperations
    from .virtual_machine_run_commands_operations_async import VirtualMachineRunCommandsOperations
except (SyntaxError, ImportError):
    from .availability_sets_operations import AvailabilitySetsOperations
    from .virtual_machine_extension_images_operations import VirtualMachineExtensionImagesOperations
    from .virtual_machine_extensions_operations import VirtualMachineExtensionsOperations
    from .virtual_machine_images_operations import VirtualMachineImagesOperations
    from .usage_operations import UsageOperations
    from .virtual_machine_sizes_operations import VirtualMachineSizesOperations
    from .images_operations import ImagesOperations
    from .resource_skus_operations import ResourceSkusOperations
    from .virtual_machines_operations import VirtualMachinesOperations
    from .virtual_machine_scale_sets_operations import VirtualMachineScaleSetsOperations
    from .virtual_machine_scale_set_extensions_operations import VirtualMachineScaleSetExtensionsOperations
    from .virtual_machine_scale_set_rolling_upgrades_operations import VirtualMachineScaleSetRollingUpgradesOperations
    from .virtual_machine_scale_set_vms_operations import VirtualMachineScaleSetVMsOperations
    from .disks_operations import DisksOperations
    from .snapshots_operations import SnapshotsOperations
    from .virtual_machine_run_commands_operations import VirtualMachineRunCommandsOperations

__all__ = [
    'AvailabilitySetsOperations',
    'VirtualMachineExtensionImagesOperations',
    'VirtualMachineExtensionsOperations',
    'VirtualMachineImagesOperations',
    'UsageOperations',
    'VirtualMachineSizesOperations',
    'ImagesOperations',
    'ResourceSkusOperations',
    'VirtualMachinesOperations',
    'VirtualMachineScaleSetsOperations',
    'VirtualMachineScaleSetExtensionsOperations',
    'VirtualMachineScaleSetRollingUpgradesOperations',
    'VirtualMachineScaleSetVMsOperations',
    'DisksOperations',
    'SnapshotsOperations',
    'VirtualMachineRunCommandsOperations',
]
