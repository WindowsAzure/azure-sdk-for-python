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
from .operations.operations import Operations
from .operations.hana_instances_operations import HanaInstancesOperations
from .operations.monitoring_operations import MonitoringOperations
from . import models


class HanaManagementClientConfiguration(AzureConfiguration):
    """Configuration for HanaManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription ID which uniquely identify Microsoft
     Azure subscription. The subscription ID forms part of the URI for every
     service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(HanaManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-hanaonazure/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class HanaManagementClient(SDKClient):
    """HANA on Azure Client

    :ivar config: Configuration for client.
    :vartype config: HanaManagementClientConfiguration

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.hanaonazure.operations.Operations
    :ivar hana_instances: HanaInstances operations
    :vartype hana_instances: azure.mgmt.hanaonazure.operations.HanaInstancesOperations
    :ivar monitoring: Monitoring operations
    :vartype monitoring: azure.mgmt.hanaonazure.operations.MonitoringOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription ID which uniquely identify Microsoft
     Azure subscription. The subscription ID forms part of the URI for every
     service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = HanaManagementClientConfiguration(credentials, subscription_id, base_url)
        super(HanaManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2017-11-03-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.hana_instances = HanaInstancesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.monitoring = MonitoringOperations(
            self._client, self.config, self._serialize, self._deserialize)
