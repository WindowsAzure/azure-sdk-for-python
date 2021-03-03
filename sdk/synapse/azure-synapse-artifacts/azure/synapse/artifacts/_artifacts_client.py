# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.core import PipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

    from azure.core.credentials import TokenCredential

from ._configuration import ArtifactsClientConfiguration
from .operations import LinkedServiceOperations
from .operations import DatasetOperations
from .operations import PipelineOperations
from .operations import PipelineRunOperations
from .operations import TriggerOperations
from .operations import TriggerRunOperations
from .operations import DataFlowOperations
from .operations import DataFlowDebugSessionOperations
from .operations import SqlScriptOperations
from .operations import SparkJobDefinitionOperations
from .operations import NotebookOperations
from .operations import WorkspaceOperations
from .operations import SqlPoolsOperations
from .operations import BigDataPoolsOperations
from .operations import IntegrationRuntimesOperations
from .operations import WorkspaceGitRepoManagementOperations
from . import models


class ArtifactsClient(object):
    """ArtifactsClient.

    :ivar linked_service: LinkedServiceOperations operations
    :vartype linked_service: azure.synapse.artifacts.operations.LinkedServiceOperations
    :ivar dataset: DatasetOperations operations
    :vartype dataset: azure.synapse.artifacts.operations.DatasetOperations
    :ivar pipeline: PipelineOperations operations
    :vartype pipeline: azure.synapse.artifacts.operations.PipelineOperations
    :ivar pipeline_run: PipelineRunOperations operations
    :vartype pipeline_run: azure.synapse.artifacts.operations.PipelineRunOperations
    :ivar trigger: TriggerOperations operations
    :vartype trigger: azure.synapse.artifacts.operations.TriggerOperations
    :ivar trigger_run: TriggerRunOperations operations
    :vartype trigger_run: azure.synapse.artifacts.operations.TriggerRunOperations
    :ivar data_flow: DataFlowOperations operations
    :vartype data_flow: azure.synapse.artifacts.operations.DataFlowOperations
    :ivar data_flow_debug_session: DataFlowDebugSessionOperations operations
    :vartype data_flow_debug_session: azure.synapse.artifacts.operations.DataFlowDebugSessionOperations
    :ivar sql_script: SqlScriptOperations operations
    :vartype sql_script: azure.synapse.artifacts.operations.SqlScriptOperations
    :ivar spark_job_definition: SparkJobDefinitionOperations operations
    :vartype spark_job_definition: azure.synapse.artifacts.operations.SparkJobDefinitionOperations
    :ivar notebook: NotebookOperations operations
    :vartype notebook: azure.synapse.artifacts.operations.NotebookOperations
    :ivar workspace: WorkspaceOperations operations
    :vartype workspace: azure.synapse.artifacts.operations.WorkspaceOperations
    :ivar sql_pools: SqlPoolsOperations operations
    :vartype sql_pools: azure.synapse.artifacts.operations.SqlPoolsOperations
    :ivar big_data_pools: BigDataPoolsOperations operations
    :vartype big_data_pools: azure.synapse.artifacts.operations.BigDataPoolsOperations
    :ivar integration_runtimes: IntegrationRuntimesOperations operations
    :vartype integration_runtimes: azure.synapse.artifacts.operations.IntegrationRuntimesOperations
    :ivar workspace_git_repo_management: WorkspaceGitRepoManagementOperations operations
    :vartype workspace_git_repo_management: azure.synapse.artifacts.operations.WorkspaceGitRepoManagementOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param endpoint: The workspace development endpoint, for example https://myworkspace.dev.azuresynapse.net.
    :type endpoint: str
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        endpoint,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        base_url = '{endpoint}'
        self._config = ArtifactsClientConfiguration(credential, endpoint, **kwargs)
        self._client = PipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.linked_service = LinkedServiceOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.dataset = DatasetOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.pipeline = PipelineOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.pipeline_run = PipelineRunOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.trigger = TriggerOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.trigger_run = TriggerRunOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.data_flow = DataFlowOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.data_flow_debug_session = DataFlowDebugSessionOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.sql_script = SqlScriptOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.spark_job_definition = SparkJobDefinitionOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.notebook = NotebookOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workspace = WorkspaceOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.sql_pools = SqlPoolsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.big_data_pools = BigDataPoolsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_runtimes = IntegrationRuntimesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workspace_git_repo_management = WorkspaceGitRepoManagementOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> ArtifactsClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
