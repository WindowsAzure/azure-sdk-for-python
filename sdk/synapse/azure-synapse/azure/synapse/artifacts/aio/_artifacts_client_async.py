# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, TYPE_CHECKING

from azure.core import AsyncPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration_async import ArtifactsClientConfiguration
from .operations_async import LinkedServiceOperations
from .operations_async import DatasetOperations
from .operations_async import PipelineOperations
from .operations_async import PipelineRunOperations
from .operations_async import TriggerOperations
from .operations_async import TriggerRunOperations
from .operations_async import DataFlowOperations
from .operations_async import DataFlowDebugSessionOperations
from .operations_async import SqlScriptOperations
from .operations_async import SparkJobDefinitionOperations
from .operations_async import NotebookOperations
from .. import models


class ArtifactsClient(object):
    """ArtifactsClient.

    :ivar linked_service: LinkedServiceOperations operations
    :vartype linked_service: azure.synapse.artifacts.aio.operations_async.LinkedServiceOperations
    :ivar dataset: DatasetOperations operations
    :vartype dataset: azure.synapse.artifacts.aio.operations_async.DatasetOperations
    :ivar pipeline: PipelineOperations operations
    :vartype pipeline: azure.synapse.artifacts.aio.operations_async.PipelineOperations
    :ivar pipeline_run: PipelineRunOperations operations
    :vartype pipeline_run: azure.synapse.artifacts.aio.operations_async.PipelineRunOperations
    :ivar trigger: TriggerOperations operations
    :vartype trigger: azure.synapse.artifacts.aio.operations_async.TriggerOperations
    :ivar trigger_run: TriggerRunOperations operations
    :vartype trigger_run: azure.synapse.artifacts.aio.operations_async.TriggerRunOperations
    :ivar data_flow: DataFlowOperations operations
    :vartype data_flow: azure.synapse.artifacts.aio.operations_async.DataFlowOperations
    :ivar data_flow_debug_session: DataFlowDebugSessionOperations operations
    :vartype data_flow_debug_session: azure.synapse.artifacts.aio.operations_async.DataFlowDebugSessionOperations
    :ivar sql_script: SqlScriptOperations operations
    :vartype sql_script: azure.synapse.artifacts.aio.operations_async.SqlScriptOperations
    :ivar spark_job_definition: SparkJobDefinitionOperations operations
    :vartype spark_job_definition: azure.synapse.artifacts.aio.operations_async.SparkJobDefinitionOperations
    :ivar notebook: NotebookOperations operations
    :vartype notebook: azure.synapse.artifacts.aio.operations_async.NotebookOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param endpoint: The workspace development endpoint, for example https://myworkspace.dev.azuresynapse.net.
    :type endpoint: str
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        endpoint: str,
        **kwargs: Any
    ) -> None:
        base_url = '{endpoint}'
        self._config = ArtifactsClientConfiguration(credential, endpoint, **kwargs)
        self._client = AsyncPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
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

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "ArtifactsClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
