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

from ._configuration import AzureReservationAPIConfiguration
from .operations import QuotaOperations
from .operations import QuotaRequestStatusOperations
from .operations import AutoQuotaIncreaseOperations
from .operations import ReservationOperations
from .operations import AzureReservationAPIOperationsMixin
from .operations import ReservationOrderOperations
from .operations import OperationOperations
from .operations import CalculateExchangeOperations
from .operations import ExchangeOperations
from .. import models


class AzureReservationAPI(AzureReservationAPIOperationsMixin):
    """Microsoft Azure Quota Resource Provider.

    :ivar quota: QuotaOperations operations
    :vartype quota: azure.mgmt.reservations.aio.operations.QuotaOperations
    :ivar quota_request_status: QuotaRequestStatusOperations operations
    :vartype quota_request_status: azure.mgmt.reservations.aio.operations.QuotaRequestStatusOperations
    :ivar auto_quota_increase: AutoQuotaIncreaseOperations operations
    :vartype auto_quota_increase: azure.mgmt.reservations.aio.operations.AutoQuotaIncreaseOperations
    :ivar reservation: ReservationOperations operations
    :vartype reservation: azure.mgmt.reservations.aio.operations.ReservationOperations
    :ivar reservation_order: ReservationOrderOperations operations
    :vartype reservation_order: azure.mgmt.reservations.aio.operations.ReservationOrderOperations
    :ivar operation: OperationOperations operations
    :vartype operation: azure.mgmt.reservations.aio.operations.OperationOperations
    :ivar calculate_exchange: CalculateExchangeOperations operations
    :vartype calculate_exchange: azure.mgmt.reservations.aio.operations.CalculateExchangeOperations
    :ivar exchange: ExchangeOperations operations
    :vartype exchange: azure.mgmt.reservations.aio.operations.ExchangeOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        base_url: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = AzureReservationAPIConfiguration(credential, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.quota = QuotaOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.quota_request_status = QuotaRequestStatusOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.auto_quota_increase = AutoQuotaIncreaseOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.reservation = ReservationOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.reservation_order = ReservationOrderOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operation = OperationOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.calculate_exchange = CalculateExchangeOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.exchange = ExchangeOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "AzureReservationAPI":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
