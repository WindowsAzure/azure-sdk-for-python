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


class HDInsightJobClientConfiguration(AzureConfiguration):
    """Configuration for HDInsightJobClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param endpoint: The cluster endpoint, for example
     https://clustername.azurehdinsight.net.
    :type endpoint: str
    :param username: The user name used for running job.
    :type username: str
    """

    def __init__(
            self, credentials, endpoint, username):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if endpoint is None:
            raise ValueError("Parameter 'endpoint' must not be None.")
        if username is None:
            raise ValueError("Parameter 'username' must not be None.")
        base_url = 'https://{endpoint}'

        super(HDInsightJobClientConfiguration, self).__init__(base_url)

        # Starting Autorest.Python 4.0.64, make connection pool activated by default
        self.keep_alive = True

        self.add_user_agent('azure-hdinsight-job/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.endpoint = endpoint
        self.username = username
