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

from ._configuration import PowerBIDedicatedManagementClientConfiguration
from .operations import CapacitiesOperations
from .operations import Operations
from . import models


class PowerBIDedicatedManagementClient(SDKClient):
    """PowerBI Dedicated Web API provides a RESTful set of web services that enables users to create, retrieve, update, and delete Power BI dedicated capacities

    :ivar config: Configuration for client.
    :vartype config: PowerBIDedicatedManagementClientConfiguration

    :ivar capacities: Capacities operations
    :vartype capacities: azure.mgmt.powerbidedicated.operations.CapacitiesOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.powerbidedicated.operations.Operations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: A unique identifier for a Microsoft Azure
     subscription. The subscription ID forms part of the URI for every service
     call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = PowerBIDedicatedManagementClientConfiguration(credentials, subscription_id, base_url)
        super(PowerBIDedicatedManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2017-10-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.capacities = CapacitiesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
