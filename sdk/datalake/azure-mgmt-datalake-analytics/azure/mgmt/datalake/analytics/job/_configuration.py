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


class DataLakeAnalyticsJobManagementClientConfiguration(AzureConfiguration):
    """Configuration for DataLakeAnalyticsJobManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param adla_job_dns_suffix: The DNS suffix used as the base for all Azure
     Data Lake Analytics Job service requests.
    :type adla_job_dns_suffix: str
    """

    def __init__(
            self, credentials, adla_job_dns_suffix):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if adla_job_dns_suffix is None:
            raise ValueError("Parameter 'adla_job_dns_suffix' must not be None.")
        base_url = 'https://{accountName}.{adlaJobDnsSuffix}'

        super(DataLakeAnalyticsJobManagementClientConfiguration, self).__init__(base_url)

        # Starting Autorest.Python 4.0.64, make connection pool activated by default
        self.keep_alive = True

        self.add_user_agent('azure-mgmt-datalake-analytics/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.adla_job_dns_suffix = adla_job_dns_suffix
