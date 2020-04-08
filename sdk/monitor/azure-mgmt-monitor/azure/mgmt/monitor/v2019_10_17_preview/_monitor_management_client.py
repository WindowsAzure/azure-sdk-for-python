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

from ._configuration import MonitorManagementClientConfiguration
from .operations import PrivateLinkScopesOperations
from .operations import PrivateLinkScopeOperationStatusOperations
from .operations import PrivateLinkResourcesOperations
from .operations import PrivateEndpointConnectionsOperations
from .operations import PrivateLinkScopedResourcesOperations
from . import models


class MonitorManagementClient(SDKClient):
    """Monitor Management Client

    :ivar config: Configuration for client.
    :vartype config: MonitorManagementClientConfiguration

    :ivar private_link_scopes: PrivateLinkScopes operations
    :vartype private_link_scopes: azure.mgmt.monitor.v2019_10_17_preview.operations.PrivateLinkScopesOperations
    :ivar private_link_scope_operation_status: PrivateLinkScopeOperationStatus operations
    :vartype private_link_scope_operation_status: azure.mgmt.monitor.v2019_10_17_preview.operations.PrivateLinkScopeOperationStatusOperations
    :ivar private_link_resources: PrivateLinkResources operations
    :vartype private_link_resources: azure.mgmt.monitor.v2019_10_17_preview.operations.PrivateLinkResourcesOperations
    :ivar private_endpoint_connections: PrivateEndpointConnections operations
    :vartype private_endpoint_connections: azure.mgmt.monitor.v2019_10_17_preview.operations.PrivateEndpointConnectionsOperations
    :ivar private_link_scoped_resources: PrivateLinkScopedResources operations
    :vartype private_link_scoped_resources: azure.mgmt.monitor.v2019_10_17_preview.operations.PrivateLinkScopedResourcesOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The Azure subscription Id.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = MonitorManagementClientConfiguration(credentials, subscription_id, base_url)
        super(MonitorManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-10-17-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.private_link_scopes = PrivateLinkScopesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.private_link_scope_operation_status = PrivateLinkScopeOperationStatusOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.private_link_resources = PrivateLinkResourcesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.private_endpoint_connections = PrivateEndpointConnectionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.private_link_scoped_resources = PrivateLinkScopedResourcesOperations(
            self._client, self.config, self._serialize, self._deserialize)
