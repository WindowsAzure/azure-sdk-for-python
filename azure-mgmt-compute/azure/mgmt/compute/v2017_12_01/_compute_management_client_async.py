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

from msrest.async_client import SDKClientAsync
from msrest import Serializer, Deserializer

from ._configuration import ComputeManagementClientConfiguration
from .operations_async import Operations
from .operations_async import AvailabilitySetsOperations
from .operations_async import VirtualMachineExtensionImagesOperations
from .operations_async import VirtualMachineExtensionsOperations
from .operations_async import VirtualMachinesOperations
from .operations_async import VirtualMachineImagesOperations
from .operations_async import UsageOperations
from .operations_async import VirtualMachineSizesOperations
from .operations_async import ImagesOperations
from .operations_async import VirtualMachineScaleSetsOperations
from .operations_async import VirtualMachineScaleSetExtensionsOperations
from .operations_async import VirtualMachineScaleSetRollingUpgradesOperations
from .operations_async import VirtualMachineScaleSetVMsOperations
from .operations_async import LogAnalyticsOperations
from .operations_async import VirtualMachineRunCommandsOperations
from . import models


class ComputeManagementClientAsync(SDKClientAsync):
    """Compute Client

    :ivar config: Configuration for client.
    :vartype config: ComputeManagementClientConfiguration

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.compute.v2017_12_01.operations.Operations
    :ivar availability_sets: AvailabilitySets operations
    :vartype availability_sets: azure.mgmt.compute.v2017_12_01.operations.AvailabilitySetsOperations
    :ivar virtual_machine_extension_images: VirtualMachineExtensionImages operations
    :vartype virtual_machine_extension_images: azure.mgmt.compute.v2017_12_01.operations.VirtualMachineExtensionImagesOperations
    :ivar virtual_machine_extensions: VirtualMachineExtensions operations
    :vartype virtual_machine_extensions: azure.mgmt.compute.v2017_12_01.operations.VirtualMachineExtensionsOperations
    :ivar virtual_machines: VirtualMachines operations
    :vartype virtual_machines: azure.mgmt.compute.v2017_12_01.operations.VirtualMachinesOperations
    :ivar virtual_machine_images: VirtualMachineImages operations
    :vartype virtual_machine_images: azure.mgmt.compute.v2017_12_01.operations.VirtualMachineImagesOperations
    :ivar usage: Usage operations
    :vartype usage: azure.mgmt.compute.v2017_12_01.operations.UsageOperations
    :ivar virtual_machine_sizes: VirtualMachineSizes operations
    :vartype virtual_machine_sizes: azure.mgmt.compute.v2017_12_01.operations.VirtualMachineSizesOperations
    :ivar images: Images operations
    :vartype images: azure.mgmt.compute.v2017_12_01.operations.ImagesOperations
    :ivar virtual_machine_scale_sets: VirtualMachineScaleSets operations
    :vartype virtual_machine_scale_sets: azure.mgmt.compute.v2017_12_01.operations.VirtualMachineScaleSetsOperations
    :ivar virtual_machine_scale_set_extensions: VirtualMachineScaleSetExtensions operations
    :vartype virtual_machine_scale_set_extensions: azure.mgmt.compute.v2017_12_01.operations.VirtualMachineScaleSetExtensionsOperations
    :ivar virtual_machine_scale_set_rolling_upgrades: VirtualMachineScaleSetRollingUpgrades operations
    :vartype virtual_machine_scale_set_rolling_upgrades: azure.mgmt.compute.v2017_12_01.operations.VirtualMachineScaleSetRollingUpgradesOperations
    :ivar virtual_machine_scale_set_vms: VirtualMachineScaleSetVMs operations
    :vartype virtual_machine_scale_set_vms: azure.mgmt.compute.v2017_12_01.operations.VirtualMachineScaleSetVMsOperations
    :ivar log_analytics: LogAnalytics operations
    :vartype log_analytics: azure.mgmt.compute.v2017_12_01.operations.LogAnalyticsOperations
    :ivar virtual_machine_run_commands: VirtualMachineRunCommands operations
    :vartype virtual_machine_run_commands: azure.mgmt.compute.v2017_12_01.operations.VirtualMachineRunCommandsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials which uniquely identify
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = ComputeManagementClientConfiguration(credentials, subscription_id, base_url)
        super(ComputeManagementClientAsync, self).__init__(self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2017-12-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.availability_sets = AvailabilitySetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_machine_extension_images = VirtualMachineExtensionImagesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_machine_extensions = VirtualMachineExtensionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_machines = VirtualMachinesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_machine_images = VirtualMachineImagesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.usage = UsageOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_machine_sizes = VirtualMachineSizesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.images = ImagesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_machine_scale_sets = VirtualMachineScaleSetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_machine_scale_set_extensions = VirtualMachineScaleSetExtensionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_machine_scale_set_rolling_upgrades = VirtualMachineScaleSetRollingUpgradesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_machine_scale_set_vms = VirtualMachineScaleSetVMsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.log_analytics = LogAnalyticsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_machine_run_commands = VirtualMachineRunCommandsOperations(
            self._client, self.config, self._serialize, self._deserialize)
