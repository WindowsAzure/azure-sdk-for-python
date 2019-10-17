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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer

from ._configuration import MicrosoftCapacityConfiguration
from .operations import MicrosoftCapacityOperationsMixin
from .operations import QuotaOperations
from .operations import QuotasOperations
from .operations import QuotaRequestsOperations
from .operations import AutoQuotaIncreaseOperations
from .operations import ReservationOperations
from .operations import ReservationOrderOperations
from .operations import OperationOperations
from . import models


class MicrosoftCapacity(MicrosoftCapacityOperationsMixin, SDKClient):
    """MicrosoftCapacity

    :ivar config: Configuration for client.
    :vartype config: MicrosoftCapacityConfiguration

    :ivar quota: Quota operations
    :vartype quota: azure.mgmt.reservations.operations.QuotaOperations
    :ivar quotas: Quotas operations
    :vartype quotas: azure.mgmt.reservations.operations.QuotasOperations
    :ivar quota_requests: QuotaRequests operations
    :vartype quota_requests: azure.mgmt.reservations.operations.QuotaRequestsOperations
    :ivar auto_quota_increase: AutoQuotaIncrease operations
    :vartype auto_quota_increase: azure.mgmt.reservations.operations.AutoQuotaIncreaseOperations
    :ivar reservation: Reservation operations
    :vartype reservation: azure.mgmt.reservations.operations.ReservationOperations
    :ivar reservation_order: ReservationOrder operations
    :vartype reservation_order: azure.mgmt.reservations.operations.ReservationOrderOperations
    :ivar operation: Operation operations
    :vartype operation: azure.mgmt.reservations.operations.OperationOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param resource_name: The Resource name for the specific resource
     provider, such as SKU name for Microsoft.Compute, pool for
     Microsoft.Batch.
    :type resource_name: str
    :param id: Quota Request id.
    :type id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, resource_name, id, base_url=None):

        self.config = MicrosoftCapacityConfiguration(credentials, resource_name, id, base_url)
        super(MicrosoftCapacity, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.quota = QuotaOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.quotas = QuotasOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.quota_requests = QuotaRequestsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.auto_quota_increase = AutoQuotaIncreaseOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.reservation = ReservationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.reservation_order = ReservationOrderOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operation = OperationOperations(
            self._client, self.config, self._serialize, self._deserialize)
