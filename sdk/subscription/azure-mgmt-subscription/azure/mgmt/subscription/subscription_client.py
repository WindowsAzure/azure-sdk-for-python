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
from msrestazure import AzureConfiguration
from .version import VERSION
from .operations.subscriptions_operations import SubscriptionsOperations
from .operations.subscription_operation_operations import SubscriptionOperationOperations
from .operations.subscription_factory_operations import SubscriptionFactoryOperations
from .operations.subscription_operations import SubscriptionOperations
from .operations.operations import Operations
from .operations.tenants_operations import TenantsOperations
from . import models


class SubscriptionClientConfiguration(AzureConfiguration):
    """Configuration for SubscriptionClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(SubscriptionClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-subscription/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials


class SubscriptionClient(SDKClient):
    """The subscription client

    :ivar config: Configuration for client.
    :vartype config: SubscriptionClientConfiguration

    :ivar subscriptions: Subscriptions operations
    :vartype subscriptions: azure.mgmt.subscription.operations.SubscriptionsOperations
    :ivar subscription_operation: SubscriptionOperation operations
    :vartype subscription_operation: azure.mgmt.subscription.operations.SubscriptionOperationOperations
    :ivar subscription_factory: SubscriptionFactory operations
    :vartype subscription_factory: azure.mgmt.subscription.operations.SubscriptionFactoryOperations
    :ivar subscription_operations: SubscriptionOperations operations
    :vartype subscription_operations: azure.mgmt.subscription.operations.SubscriptionOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.subscription.operations.Operations
    :ivar tenants: Tenants operations
    :vartype tenants: azure.mgmt.subscription.operations.TenantsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, base_url=None):

        self.config = SubscriptionClientConfiguration(credentials, base_url)
        super(SubscriptionClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.subscriptions = SubscriptionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.subscription_operation = SubscriptionOperationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.subscription_factory = SubscriptionFactoryOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.subscription_operations = SubscriptionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tenants = TenantsOperations(
            self._client, self.config, self._serialize, self._deserialize)
