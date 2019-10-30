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

from ._configuration import HybridComputeManagementClientConfiguration
from .operations import MachinesOperations
from .operations import Operations
from . import models


class HybridComputeManagementClient(SDKClient):
    """The Hybrid Compute Management Client.

    :ivar config: Configuration for client.
    :vartype config: HybridComputeManagementClientConfiguration

    :ivar machines: Machines operations
    :vartype machines: azure.mgmt.hybridcompute.operations.MachinesOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.hybridcompute.operations.Operations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials which uniquely identify
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = HybridComputeManagementClientConfiguration(credentials, subscription_id, base_url)
        super(HybridComputeManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-08-02-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.machines = MachinesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
