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

from ._configuration import ResourceGraphClientConfiguration
from .operations import ResourceGraphClientOperationsMixin
from .operations import Operations
from .operations import GraphQueryOperations
from . import models


class ResourceGraphClient(ResourceGraphClientOperationsMixin, SDKClient):
    """ResourceGraphClient

    :ivar config: Configuration for client.
    :vartype config: ResourceGraphClientConfiguration

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.resourcegraph.operations.Operations
    :ivar graph_query: GraphQuery operations
    :vartype graph_query: azure.mgmt.resourcegraph.operations.GraphQueryOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The Azure subscription Id.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = ResourceGraphClientConfiguration(credentials, subscription_id, base_url)
        super(ResourceGraphClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.graph_query = GraphQueryOperations(
            self._client, self.config, self._serialize, self._deserialize)
