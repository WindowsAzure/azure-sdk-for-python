# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, Optional, TYPE_CHECKING

from azure.mgmt.core import AsyncARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration_async import ComputeManagementClientConfiguration
from .operations_async import AvailabilitySetsOperations
from .operations_async import VirtualMachineExtensionImagesOperations
from .operations_async import VirtualMachineExtensionsOperations
from .operations_async import VirtualMachinesOperations
from .operations_async import VirtualMachineImagesOperations
from .operations_async import UsageOperations
from .operations_async import VirtualMachineSizesOperations
from .operations_async import ImagesOperations
from .operations_async import VirtualMachineScaleSetsOperations
from .operations_async import VirtualMachineScaleSetVMsOperations
from .operations_async import DisksOperations
from .operations_async import SnapshotsOperations
from .. import models


class ComputeManagementClient(object):
    """Compute Client.

    :ivar availability_sets: AvailabilitySetsOperations operations
    :vartype availability_sets: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.AvailabilitySetsOperations
    :ivar virtual_machine_extension_images: VirtualMachineExtensionImagesOperations operations
    :vartype virtual_machine_extension_images: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.VirtualMachineExtensionImagesOperations
    :ivar virtual_machine_extensions: VirtualMachineExtensionsOperations operations
    :vartype virtual_machine_extensions: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.VirtualMachineExtensionsOperations
    :ivar virtual_machines: VirtualMachinesOperations operations
    :vartype virtual_machines: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.VirtualMachinesOperations
    :ivar virtual_machine_images: VirtualMachineImagesOperations operations
    :vartype virtual_machine_images: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.VirtualMachineImagesOperations
    :ivar usage: UsageOperations operations
    :vartype usage: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.UsageOperations
    :ivar virtual_machine_sizes: VirtualMachineSizesOperations operations
    :vartype virtual_machine_sizes: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.VirtualMachineSizesOperations
    :ivar images: ImagesOperations operations
    :vartype images: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.ImagesOperations
    :ivar virtual_machine_scale_sets: VirtualMachineScaleSetsOperations operations
    :vartype virtual_machine_scale_sets: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.VirtualMachineScaleSetsOperations
    :ivar virtual_machine_scale_set_vms: VirtualMachineScaleSetVMsOperations operations
    :vartype virtual_machine_scale_set_vms: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.VirtualMachineScaleSetVMsOperations
    :ivar disks: DisksOperations operations
    :vartype disks: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.DisksOperations
    :ivar snapshots: SnapshotsOperations operations
    :vartype snapshots: azure.mgmt.compute.v2016_04_30_preview.aio.operations_async.SnapshotsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: Subscription credentials which uniquely identify Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        subscription_id: str,
        base_url: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = ComputeManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.availability_sets = AvailabilitySetsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machine_extension_images = VirtualMachineExtensionImagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machine_extensions = VirtualMachineExtensionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machines = VirtualMachinesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machine_images = VirtualMachineImagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.usage = UsageOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machine_sizes = VirtualMachineSizesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.images = ImagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machine_scale_sets = VirtualMachineScaleSetsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machine_scale_set_vms = VirtualMachineScaleSetVMsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.disks = DisksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.snapshots = SnapshotsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "ComputeManagementClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
