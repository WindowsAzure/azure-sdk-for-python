# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, Optional, TYPE_CHECKING

from azure.mgmt.core import AsyncARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration import DataMigrationManagementClientConfiguration
from .operations import ResourceSkusOperations
from .operations import ServicesOperations
from .operations import TasksOperations
from .operations import ServiceTasksOperations
from .operations import ProjectsOperations
from .operations import UsagesOperations
from .operations import Operations
from .operations import FilesOperations
from .. import models


class DataMigrationManagementClient(object):
    """Data Migration Client.

    :ivar resource_skus: ResourceSkusOperations operations
    :vartype resource_skus: azure.mgmt.datamigration.aio.operations.ResourceSkusOperations
    :ivar services: ServicesOperations operations
    :vartype services: azure.mgmt.datamigration.aio.operations.ServicesOperations
    :ivar tasks: TasksOperations operations
    :vartype tasks: azure.mgmt.datamigration.aio.operations.TasksOperations
    :ivar service_tasks: ServiceTasksOperations operations
    :vartype service_tasks: azure.mgmt.datamigration.aio.operations.ServiceTasksOperations
    :ivar projects: ProjectsOperations operations
    :vartype projects: azure.mgmt.datamigration.aio.operations.ProjectsOperations
    :ivar usages: UsagesOperations operations
    :vartype usages: azure.mgmt.datamigration.aio.operations.UsagesOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.datamigration.aio.operations.Operations
    :ivar files: FilesOperations operations
    :vartype files: azure.mgmt.datamigration.aio.operations.FilesOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: Identifier of the subscription.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        subscription_id: str,
        base_url: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = DataMigrationManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.resource_skus = ResourceSkusOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.services = ServicesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.tasks = TasksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.service_tasks = ServiceTasksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.projects = ProjectsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.usages = UsagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.files = FilesOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "DataMigrationManagementClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
