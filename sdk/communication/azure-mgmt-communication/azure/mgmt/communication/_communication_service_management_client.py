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

from ._configuration import CommunicationServiceManagementClientConfiguration
from .operations import Operations
from .operations import CommunicationServiceOperations
from .operations import OperationStatusesOperations
from . import models


class CommunicationServiceManagementClient(SDKClient):
    """REST API for Azure Communication Services

    :ivar config: Configuration for client.
    :vartype config: CommunicationServiceManagementClientConfiguration

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.communication.operations.Operations
    :ivar communication_service: CommunicationService operations
    :vartype communication_service: azure.mgmt.communication.operations.CommunicationServiceOperations
    :ivar operation_statuses: OperationStatuses operations
    :vartype operation_statuses: azure.mgmt.communication.operations.OperationStatusesOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Gets subscription ID which uniquely identifies the
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = CommunicationServiceManagementClientConfiguration(credentials, subscription_id, base_url)
        super(CommunicationServiceManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2020-08-20-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.communication_service = CommunicationServiceOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operation_statuses = OperationStatusesOperations(
            self._client, self.config, self._serialize, self._deserialize)
