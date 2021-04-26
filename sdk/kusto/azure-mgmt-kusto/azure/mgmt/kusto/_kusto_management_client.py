# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.mgmt.core import ARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Optional

    from azure.core.credentials import TokenCredential
    from azure.core.pipeline.transport import HttpRequest, HttpResponse

from ._configuration import KustoManagementClientConfiguration
from .operations import ClustersOperations
from .operations import ClusterPrincipalAssignmentsOperations
from .operations import DatabasesOperations
from .operations import DatabasePrincipalAssignmentsOperations
from .operations import ScriptsOperations
from .operations import AttachedDatabaseConfigurationsOperations
from .operations import DataConnectionsOperations
from .operations import Operations
from .operations import OperationsResultsOperations
from . import models


class KustoManagementClient(object):
    """The Azure Kusto management API provides a RESTful set of web services that interact with Azure Kusto services to manage your clusters and databases. The API enables you to create, update, and delete clusters and databases.

    :ivar clusters: ClustersOperations operations
    :vartype clusters: azure.mgmt.kusto.operations.ClustersOperations
    :ivar cluster_principal_assignments: ClusterPrincipalAssignmentsOperations operations
    :vartype cluster_principal_assignments: azure.mgmt.kusto.operations.ClusterPrincipalAssignmentsOperations
    :ivar databases: DatabasesOperations operations
    :vartype databases: azure.mgmt.kusto.operations.DatabasesOperations
    :ivar database_principal_assignments: DatabasePrincipalAssignmentsOperations operations
    :vartype database_principal_assignments: azure.mgmt.kusto.operations.DatabasePrincipalAssignmentsOperations
    :ivar scripts: ScriptsOperations operations
    :vartype scripts: azure.mgmt.kusto.operations.ScriptsOperations
    :ivar attached_database_configurations: AttachedDatabaseConfigurationsOperations operations
    :vartype attached_database_configurations: azure.mgmt.kusto.operations.AttachedDatabaseConfigurationsOperations
    :ivar data_connections: DataConnectionsOperations operations
    :vartype data_connections: azure.mgmt.kusto.operations.DataConnectionsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.kusto.operations.Operations
    :ivar operations_results: OperationsResultsOperations operations
    :vartype operations_results: azure.mgmt.kusto.operations.OperationsResultsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: Gets subscription credentials which uniquely identify Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        subscription_id,  # type: str
        base_url=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = KustoManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.clusters = ClustersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.cluster_principal_assignments = ClusterPrincipalAssignmentsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.databases = DatabasesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.database_principal_assignments = DatabasePrincipalAssignmentsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.scripts = ScriptsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.attached_database_configurations = AttachedDatabaseConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.data_connections = DataConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations_results = OperationsResultsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def _send_request(self, http_request, **kwargs):
        # type: (HttpRequest, Any) -> HttpResponse
        """Runs the network request through the client's chained policies.

        :param http_request: The network request you want to make. Required.
        :type http_request: ~azure.core.pipeline.transport.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to True.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.pipeline.transport.HttpResponse
        """
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        http_request.url = self._client.format_url(http_request.url, **path_format_arguments)
        stream = kwargs.pop("stream", True)
        pipeline_response = self._client._pipeline.run(http_request, stream=stream, **kwargs)
        return pipeline_response.http_response

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> KustoManagementClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
