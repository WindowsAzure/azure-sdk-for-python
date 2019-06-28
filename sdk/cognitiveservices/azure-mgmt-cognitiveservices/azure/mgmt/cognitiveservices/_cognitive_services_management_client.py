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

from ._configuration import CognitiveServicesManagementClientConfiguration
from .operations import CognitiveServicesManagementClientOperationsMixin
from .operations import AccountsOperations
from .operations import ResourceSkusOperations
from .operations import Operations
from .operations import CheckSkuAvailabilityOperations
from . import models


class CognitiveServicesManagementClient(CognitiveServicesManagementClientOperationsMixin, SDKClient):
    """Cognitive Services Management Client

    :ivar config: Configuration for client.
    :vartype config: CognitiveServicesManagementClientConfiguration

    :ivar accounts: Accounts operations
    :vartype accounts: azure.mgmt.cognitiveservices.operations.AccountsOperations
    :ivar resource_skus: ResourceSkus operations
    :vartype resource_skus: azure.mgmt.cognitiveservices.operations.ResourceSkusOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.cognitiveservices.operations.Operations
    :ivar check_sku_availability: CheckSkuAvailability operations
    :vartype check_sku_availability: azure.mgmt.cognitiveservices.operations.CheckSkuAvailabilityOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure Subscription ID.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = CognitiveServicesManagementClientConfiguration(credentials, subscription_id, base_url)
        super(CognitiveServicesManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2017-04-18'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.accounts = AccountsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.resource_skus = ResourceSkusOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.check_sku_availability = CheckSkuAvailabilityOperations(
            self._client, self.config, self._serialize, self._deserialize)
