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

from ._configuration import CostManagementClientConfiguration
from .operations import ViewsOperations
from .operations import AlertsOperations
from .operations import ForecastOperations
from .operations import DimensionsOperations
from .operations import QueryOperations
from .operations import ExportsOperations
from .operations import Operations
from . import models


class CostManagementClient(SDKClient):
    """CostManagementClient

    :ivar config: Configuration for client.
    :vartype config: CostManagementClientConfiguration

    :ivar views: Views operations
    :vartype views: azure.mgmt.costmanagement.operations.ViewsOperations
    :ivar alerts: Alerts operations
    :vartype alerts: azure.mgmt.costmanagement.operations.AlertsOperations
    :ivar forecast: Forecast operations
    :vartype forecast: azure.mgmt.costmanagement.operations.ForecastOperations
    :ivar dimensions: Dimensions operations
    :vartype dimensions: azure.mgmt.costmanagement.operations.DimensionsOperations
    :ivar query: Query operations
    :vartype query: azure.mgmt.costmanagement.operations.QueryOperations
    :ivar exports: Exports operations
    :vartype exports: azure.mgmt.costmanagement.operations.ExportsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.costmanagement.operations.Operations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure Subscription ID.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = CostManagementClientConfiguration(credentials, subscription_id, base_url)
        super(CostManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-11-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.views = ViewsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.alerts = AlertsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.forecast = ForecastOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.dimensions = DimensionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.query = QueryOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.exports = ExportsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
