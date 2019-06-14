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

from ._configuration import ManagementLockClientConfiguration
from .operations import AuthorizationOperations
from .operations import ManagementLocksOperations
from . import models


class ManagementLockClient(SDKClient):
    """Azure resources can be locked to prevent other users in your organization from deleting or modifying resources.

    :ivar config: Configuration for client.
    :vartype config: ManagementLockClientConfiguration

    :ivar authorization_operations: AuthorizationOperations operations
    :vartype authorization_operations: azure.mgmt.resource.locks.v2016_09_01.operations.AuthorizationOperations
    :ivar management_locks: ManagementLocks operations
    :vartype management_locks: azure.mgmt.resource.locks.v2016_09_01.operations.ManagementLocksOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The ID of the target subscription.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = ManagementLockClientConfiguration(credentials, subscription_id, base_url)
        super(ManagementLockClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2016-09-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.authorization_operations = AuthorizationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.management_locks = ManagementLocksOperations(
            self._client, self.config, self._serialize, self._deserialize)
