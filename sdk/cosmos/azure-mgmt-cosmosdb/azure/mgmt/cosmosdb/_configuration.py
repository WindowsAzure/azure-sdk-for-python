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
from msrestazure import AzureConfiguration

from .version import VERSION


class CosmosDBManagementClientConfiguration(AzureConfiguration):
    """Configuration for CosmosDBManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure subscription ID.
    :type subscription_id: str
    :param subscription_id1: The ID of the target subscription.
    :type subscription_id1: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, subscription_id1, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if subscription_id1 is None:
            raise ValueError("Parameter 'subscription_id1' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(CosmosDBManagementClientConfiguration, self).__init__(base_url)

        # Starting Autorest.Python 4.0.64, make connection pool activated by default
        self.keep_alive = True

        self.add_user_agent('azure-mgmt-cosmosdb/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id
        self.subscription_id1 = subscription_id1
