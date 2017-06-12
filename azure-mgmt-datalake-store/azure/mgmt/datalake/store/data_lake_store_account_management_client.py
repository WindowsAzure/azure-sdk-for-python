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
from .operations.firewall_rules_operations import FirewallRulesOperations
from .operations.trusted_id_providers_operations import TrustedIdProvidersOperations
from .operations.account_operations import AccountOperations
from . import models


class DataLakeStoreAccountManagementClientConfiguration(AzureConfiguration):
    """Configuration for DataLakeStoreAccountManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Gets subscription credentials which uniquely
     identify Microsoft Azure subscription. The subscription ID forms part of
     the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not isinstance(subscription_id, str):
            raise TypeError("Parameter 'subscription_id' must be str.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(DataLakeStoreAccountManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('datalakestoreaccountmanagementclient/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class DataLakeStoreAccountManagementClient(object):
    """Creates an Azure Data Lake Store account management client.

    :ivar config: Configuration for client.
    :vartype config: DataLakeStoreAccountManagementClientConfiguration

    :ivar firewall_rules: FirewallRules operations
    :vartype firewall_rules: azure.mgmt.datalake.store.operations.FirewallRulesOperations
    :ivar trusted_id_providers: TrustedIdProviders operations
    :vartype trusted_id_providers: azure.mgmt.datalake.store.operations.TrustedIdProvidersOperations
    :ivar account: Account operations
    :vartype account: azure.mgmt.datalake.store.operations.AccountOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Gets subscription credentials which uniquely
     identify Microsoft Azure subscription. The subscription ID forms part of
     the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = DataLakeStoreAccountManagementClientConfiguration(credentials, subscription_id, base_url)
        self._client = ServiceClient(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2016-11-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.firewall_rules = FirewallRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.trusted_id_providers = TrustedIdProvidersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.account = AccountOperations(
            self._client, self.config, self._serialize, self._deserialize)
