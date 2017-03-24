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
from .operations.catalog_operations import CatalogOperations
from . import models


class DataLakeAnalyticsCatalogManagementClientConfiguration(AzureConfiguration):
    """Configuration for DataLakeAnalyticsCatalogManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param adla_catalog_dns_suffix: Gets the DNS suffix used as the base for
     all Azure Data Lake Analytics Catalog service requests.
    :type adla_catalog_dns_suffix: str
    """

    def __init__(
            self, credentials, adla_catalog_dns_suffix):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if adla_catalog_dns_suffix is None:
            raise ValueError("Parameter 'adla_catalog_dns_suffix' must not be None.")
        if not isinstance(adla_catalog_dns_suffix, str):
            raise TypeError("Parameter 'adla_catalog_dns_suffix' must be str.")
        base_url = 'https://{accountName}.{adlaCatalogDnsSuffix}'

        super(DataLakeAnalyticsCatalogManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('datalakeanalyticscatalogmanagementclient/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.adla_catalog_dns_suffix = adla_catalog_dns_suffix


class DataLakeAnalyticsCatalogManagementClient(object):
    """Creates an Azure Data Lake Analytics catalog client.

    :ivar config: Configuration for client.
    :vartype config: DataLakeAnalyticsCatalogManagementClientConfiguration

    :ivar catalog: Catalog operations
    :vartype catalog: .operations.CatalogOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param adla_catalog_dns_suffix: Gets the DNS suffix used as the base for
     all Azure Data Lake Analytics Catalog service requests.
    :type adla_catalog_dns_suffix: str
    """

    def __init__(
            self, credentials, adla_catalog_dns_suffix):

        self.config = DataLakeAnalyticsCatalogManagementClientConfiguration(credentials, adla_catalog_dns_suffix)
        self._client = ServiceClient(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2016-11-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.catalog = CatalogOperations(
            self._client, self.config, self._serialize, self._deserialize)
