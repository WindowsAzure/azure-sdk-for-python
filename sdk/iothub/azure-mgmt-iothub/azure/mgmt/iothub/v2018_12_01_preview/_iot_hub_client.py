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

from ._configuration import IotHubClientConfiguration
from .operations import Operations
from .operations import IotHubResourceOperations
from .operations import ResourceProviderCommonOperations
from .operations import CertificatesOperations
from . import models


class IotHubClient(SDKClient):
    """Use this API to manage the IoT hubs in your Azure subscription.

    :ivar config: Configuration for client.
    :vartype config: IotHubClientConfiguration

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.iothub.operations.Operations
    :ivar iot_hub_resource: IotHubResource operations
    :vartype iot_hub_resource: azure.mgmt.iothub.operations.IotHubResourceOperations
    :ivar resource_provider_common: ResourceProviderCommon operations
    :vartype resource_provider_common: azure.mgmt.iothub.operations.ResourceProviderCommonOperations
    :ivar certificates: Certificates operations
    :vartype certificates: azure.mgmt.iothub.operations.CertificatesOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The subscription identifier.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = IotHubClientConfiguration(credentials, subscription_id, base_url)
        super(IotHubClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-12-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_hub_resource = IotHubResourceOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.resource_provider_common = ResourceProviderCommonOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.certificates = CertificatesOperations(
            self._client, self.config, self._serialize, self._deserialize)
