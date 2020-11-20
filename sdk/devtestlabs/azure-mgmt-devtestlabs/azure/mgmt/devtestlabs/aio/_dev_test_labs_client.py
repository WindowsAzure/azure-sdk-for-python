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

from ._configuration import DevTestLabsClientConfiguration
from .operations import ProviderOperationsOperations
from .operations import LabsOperations
from .operations import Operations
from .operations import GlobalSchedulesOperations
from .operations import ArtifactSourcesOperations
from .operations import ArmTemplatesOperations
from .operations import ArtifactsOperations
from .operations import CostsOperations
from .operations import CustomImagesOperations
from .operations import FormulasOperations
from .operations import GalleryImagesOperations
from .operations import NotificationChannelsOperations
from .operations import PolicySetsOperations
from .operations import PoliciesOperations
from .operations import SchedulesOperations
from .operations import ServiceRunnersOperations
from .operations import UsersOperations
from .operations import DisksOperations
from .operations import EnvironmentsOperations
from .operations import SecretsOperations
from .operations import ServiceFabricsOperations
from .operations import ServiceFabricSchedulesOperations
from .operations import VirtualMachinesOperations
from .operations import VirtualMachineSchedulesOperations
from .operations import VirtualNetworksOperations
from .. import models


class DevTestLabsClient(object):
    """The DevTest Labs Client.

    :ivar provider_operations: ProviderOperationsOperations operations
    :vartype provider_operations: azure.mgmt.devtestlabs.aio.operations.ProviderOperationsOperations
    :ivar labs: LabsOperations operations
    :vartype labs: azure.mgmt.devtestlabs.aio.operations.LabsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.devtestlabs.aio.operations.Operations
    :ivar global_schedules: GlobalSchedulesOperations operations
    :vartype global_schedules: azure.mgmt.devtestlabs.aio.operations.GlobalSchedulesOperations
    :ivar artifact_sources: ArtifactSourcesOperations operations
    :vartype artifact_sources: azure.mgmt.devtestlabs.aio.operations.ArtifactSourcesOperations
    :ivar arm_templates: ArmTemplatesOperations operations
    :vartype arm_templates: azure.mgmt.devtestlabs.aio.operations.ArmTemplatesOperations
    :ivar artifacts: ArtifactsOperations operations
    :vartype artifacts: azure.mgmt.devtestlabs.aio.operations.ArtifactsOperations
    :ivar costs: CostsOperations operations
    :vartype costs: azure.mgmt.devtestlabs.aio.operations.CostsOperations
    :ivar custom_images: CustomImagesOperations operations
    :vartype custom_images: azure.mgmt.devtestlabs.aio.operations.CustomImagesOperations
    :ivar formulas: FormulasOperations operations
    :vartype formulas: azure.mgmt.devtestlabs.aio.operations.FormulasOperations
    :ivar gallery_images: GalleryImagesOperations operations
    :vartype gallery_images: azure.mgmt.devtestlabs.aio.operations.GalleryImagesOperations
    :ivar notification_channels: NotificationChannelsOperations operations
    :vartype notification_channels: azure.mgmt.devtestlabs.aio.operations.NotificationChannelsOperations
    :ivar policy_sets: PolicySetsOperations operations
    :vartype policy_sets: azure.mgmt.devtestlabs.aio.operations.PolicySetsOperations
    :ivar policies: PoliciesOperations operations
    :vartype policies: azure.mgmt.devtestlabs.aio.operations.PoliciesOperations
    :ivar schedules: SchedulesOperations operations
    :vartype schedules: azure.mgmt.devtestlabs.aio.operations.SchedulesOperations
    :ivar service_runners: ServiceRunnersOperations operations
    :vartype service_runners: azure.mgmt.devtestlabs.aio.operations.ServiceRunnersOperations
    :ivar users: UsersOperations operations
    :vartype users: azure.mgmt.devtestlabs.aio.operations.UsersOperations
    :ivar disks: DisksOperations operations
    :vartype disks: azure.mgmt.devtestlabs.aio.operations.DisksOperations
    :ivar environments: EnvironmentsOperations operations
    :vartype environments: azure.mgmt.devtestlabs.aio.operations.EnvironmentsOperations
    :ivar secrets: SecretsOperations operations
    :vartype secrets: azure.mgmt.devtestlabs.aio.operations.SecretsOperations
    :ivar service_fabrics: ServiceFabricsOperations operations
    :vartype service_fabrics: azure.mgmt.devtestlabs.aio.operations.ServiceFabricsOperations
    :ivar service_fabric_schedules: ServiceFabricSchedulesOperations operations
    :vartype service_fabric_schedules: azure.mgmt.devtestlabs.aio.operations.ServiceFabricSchedulesOperations
    :ivar virtual_machines: VirtualMachinesOperations operations
    :vartype virtual_machines: azure.mgmt.devtestlabs.aio.operations.VirtualMachinesOperations
    :ivar virtual_machine_schedules: VirtualMachineSchedulesOperations operations
    :vartype virtual_machine_schedules: azure.mgmt.devtestlabs.aio.operations.VirtualMachineSchedulesOperations
    :ivar virtual_networks: VirtualNetworksOperations operations
    :vartype virtual_networks: azure.mgmt.devtestlabs.aio.operations.VirtualNetworksOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: The subscription ID.
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
        self._config = DevTestLabsClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.provider_operations = ProviderOperationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.labs = LabsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.global_schedules = GlobalSchedulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.artifact_sources = ArtifactSourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.arm_templates = ArmTemplatesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.artifacts = ArtifactsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.costs = CostsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.custom_images = CustomImagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.formulas = FormulasOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.gallery_images = GalleryImagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.notification_channels = NotificationChannelsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.policy_sets = PolicySetsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.policies = PoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.schedules = SchedulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.service_runners = ServiceRunnersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.users = UsersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.disks = DisksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.environments = EnvironmentsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.secrets = SecretsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.service_fabrics = ServiceFabricsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.service_fabric_schedules = ServiceFabricSchedulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machines = VirtualMachinesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machine_schedules = VirtualMachineSchedulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_networks = VirtualNetworksOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "DevTestLabsClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
