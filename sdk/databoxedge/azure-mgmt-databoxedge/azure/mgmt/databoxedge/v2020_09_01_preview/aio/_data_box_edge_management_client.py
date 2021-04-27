# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, Optional, TYPE_CHECKING

from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.mgmt.core import AsyncARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration import DataBoxEdgeManagementClientConfiguration
from .operations import Operations
from .operations import AvailableSkusOperations
from .operations import DevicesOperations
from .operations import AlertsOperations
from .operations import BandwidthSchedulesOperations
from .operations import JobsOperations
from .operations import NodesOperations
from .operations import OperationsStatusOperations
from .operations import OrdersOperations
from .operations import RolesOperations
from .operations import AddonsOperations
from .operations import MonitoringConfigOperations
from .operations import SharesOperations
from .operations import StorageAccountCredentialsOperations
from .operations import StorageAccountsOperations
from .operations import ContainersOperations
from .operations import TriggersOperations
from .operations import UsersOperations
from .. import models


class DataBoxEdgeManagementClient(object):
    """The DataBoxEdge Client.

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.Operations
    :ivar available_skus: AvailableSkusOperations operations
    :vartype available_skus: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.AvailableSkusOperations
    :ivar devices: DevicesOperations operations
    :vartype devices: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.DevicesOperations
    :ivar alerts: AlertsOperations operations
    :vartype alerts: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.AlertsOperations
    :ivar bandwidth_schedules: BandwidthSchedulesOperations operations
    :vartype bandwidth_schedules: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.BandwidthSchedulesOperations
    :ivar jobs: JobsOperations operations
    :vartype jobs: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.JobsOperations
    :ivar nodes: NodesOperations operations
    :vartype nodes: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.NodesOperations
    :ivar operations_status: OperationsStatusOperations operations
    :vartype operations_status: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.OperationsStatusOperations
    :ivar orders: OrdersOperations operations
    :vartype orders: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.OrdersOperations
    :ivar roles: RolesOperations operations
    :vartype roles: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.RolesOperations
    :ivar addons: AddonsOperations operations
    :vartype addons: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.AddonsOperations
    :ivar monitoring_config: MonitoringConfigOperations operations
    :vartype monitoring_config: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.MonitoringConfigOperations
    :ivar shares: SharesOperations operations
    :vartype shares: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.SharesOperations
    :ivar storage_account_credentials: StorageAccountCredentialsOperations operations
    :vartype storage_account_credentials: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.StorageAccountCredentialsOperations
    :ivar storage_accounts: StorageAccountsOperations operations
    :vartype storage_accounts: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.StorageAccountsOperations
    :ivar containers: ContainersOperations operations
    :vartype containers: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.ContainersOperations
    :ivar triggers: TriggersOperations operations
    :vartype triggers: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.TriggersOperations
    :ivar users: UsersOperations operations
    :vartype users: azure.mgmt.databoxedge.v2020_09_01_preview.aio.operations.UsersOperations
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
        self._config = DataBoxEdgeManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.available_skus = AvailableSkusOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.devices = DevicesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.alerts = AlertsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.bandwidth_schedules = BandwidthSchedulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.jobs = JobsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.nodes = NodesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations_status = OperationsStatusOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.orders = OrdersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.roles = RolesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.addons = AddonsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.monitoring_config = MonitoringConfigOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.shares = SharesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.storage_account_credentials = StorageAccountCredentialsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.storage_accounts = StorageAccountsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.containers = ContainersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.triggers = TriggersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.users = UsersOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def _send_request(self, http_request: HttpRequest, **kwargs: Any) -> AsyncHttpResponse:
        """Runs the network request through the client's chained policies.

        :param http_request: The network request you want to make. Required.
        :type http_request: ~azure.core.pipeline.transport.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to True.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.pipeline.transport.AsyncHttpResponse
        """
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        http_request.url = self._client.format_url(http_request.url, **path_format_arguments)
        stream = kwargs.pop("stream", True)
        pipeline_response = await self._client._pipeline.run(http_request, stream=stream, **kwargs)
        return pipeline_response.http_response

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "DataBoxEdgeManagementClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
