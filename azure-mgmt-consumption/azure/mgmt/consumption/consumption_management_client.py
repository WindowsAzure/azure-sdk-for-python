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

from msrest.service_client import ServiceClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from .operations.usage_details_operations import UsageDetailsOperations
from .operations.marketplaces_operations import MarketplacesOperations
from .operations.reservations_summaries_operations import ReservationsSummariesOperations
from .operations.reservations_details_operations import ReservationsDetailsOperations
from .operations.reservation_recommendations_operations import ReservationRecommendationsOperations
from .operations.budgets_operations import BudgetsOperations
from .operations.operations import Operations
from .operations.price_sheet_operations import PriceSheetOperations
from .operations.cost_allocation_tags_operations import CostAllocationTagsOperations
from . import models


class ConsumptionManagementClientConfiguration(AzureConfiguration):
    """Configuration for ConsumptionManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure Subscription ID.
    :type subscription_id: str
    :param billing_account_id: Azure Billing Account ID.
    :type billing_account_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, billing_account_id, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if billing_account_id is None:
            raise ValueError("Parameter 'billing_account_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(ConsumptionManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-consumption/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id
        self.billing_account_id = billing_account_id


class ConsumptionManagementClient(object):
    """Consumption management client provides access to consumption resources for Azure Enterprise Subscriptions.

    :ivar config: Configuration for client.
    :vartype config: ConsumptionManagementClientConfiguration

    :ivar usage_details: UsageDetails operations
    :vartype usage_details: azure.mgmt.consumption.operations.UsageDetailsOperations
    :ivar marketplaces: Marketplaces operations
    :vartype marketplaces: azure.mgmt.consumption.operations.MarketplacesOperations
    :ivar reservations_summaries: ReservationsSummaries operations
    :vartype reservations_summaries: azure.mgmt.consumption.operations.ReservationsSummariesOperations
    :ivar reservations_details: ReservationsDetails operations
    :vartype reservations_details: azure.mgmt.consumption.operations.ReservationsDetailsOperations
    :ivar reservation_recommendations: ReservationRecommendations operations
    :vartype reservation_recommendations: azure.mgmt.consumption.operations.ReservationRecommendationsOperations
    :ivar budgets: Budgets operations
    :vartype budgets: azure.mgmt.consumption.operations.BudgetsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.consumption.operations.Operations
    :ivar price_sheet: PriceSheet operations
    :vartype price_sheet: azure.mgmt.consumption.operations.PriceSheetOperations
    :ivar cost_allocation_tags: CostAllocationTags operations
    :vartype cost_allocation_tags: azure.mgmt.consumption.operations.CostAllocationTagsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure Subscription ID.
    :type subscription_id: str
    :param billing_account_id: Azure Billing Account ID.
    :type billing_account_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, billing_account_id, base_url=None):

        self.config = ConsumptionManagementClientConfiguration(credentials, subscription_id, billing_account_id, base_url)
        self._client = ServiceClient(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-03-31'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.usage_details = UsageDetailsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.marketplaces = MarketplacesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.reservations_summaries = ReservationsSummariesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.reservations_details = ReservationsDetailsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.reservation_recommendations = ReservationRecommendationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.budgets = BudgetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.price_sheet = PriceSheetOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.cost_allocation_tags = CostAllocationTagsOperations(
            self._client, self.config, self._serialize, self._deserialize)
