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
from .operations.record_sets_operations import RecordSetsOperations
from .operations.zones_operations import ZonesOperations
from . import models


class DnsManagementClientConfiguration(AzureConfiguration):
    """Configuration for DnsManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The ID of the target subscription.
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

        super(DnsManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-dns/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class DnsManagementClient(SDKClient):
    """The DNS Management Client.

    :ivar config: Configuration for client.
    :vartype config: DnsManagementClientConfiguration

    :ivar record_sets: RecordSets operations
    :vartype record_sets: azure.mgmt.dns.v2018_03_01_preview.operations.RecordSetsOperations
    :ivar zones: Zones operations
    :vartype zones: azure.mgmt.dns.v2018_03_01_preview.operations.ZonesOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The ID of the target subscription.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = DnsManagementClientConfiguration(credentials, subscription_id, base_url)
        super(DnsManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-03-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.record_sets = RecordSetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.zones = ZonesOperations(
            self._client, self.config, self._serialize, self._deserialize)
