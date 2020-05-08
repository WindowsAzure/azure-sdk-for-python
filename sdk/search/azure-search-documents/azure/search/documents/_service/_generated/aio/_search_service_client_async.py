# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any

from azure.core import AsyncPipelineClient
from msrest import Deserializer, Serializer

from ._configuration_async import SearchServiceClientConfiguration
from .operations_async import DataSourcesOperations
from .operations_async import IndexersOperations
from .operations_async import SkillsetsOperations
from .operations_async import SynonymMapsOperations
from .operations_async import IndexesOperations
from .operations_async import SearchServiceClientOperationsMixin
from .. import models


class SearchServiceClient(SearchServiceClientOperationsMixin):
    """Client that can be used to manage and query indexes and documents, as well as manage other resources, on a search service.

    :ivar data_sources: DataSourcesOperations operations
    :vartype data_sources: azure.search.documents.aio.operations_async.DataSourcesOperations
    :ivar indexers: IndexersOperations operations
    :vartype indexers: azure.search.documents.aio.operations_async.IndexersOperations
    :ivar skillsets: SkillsetsOperations operations
    :vartype skillsets: azure.search.documents.aio.operations_async.SkillsetsOperations
    :ivar synonym_maps: SynonymMapsOperations operations
    :vartype synonym_maps: azure.search.documents.aio.operations_async.SynonymMapsOperations
    :ivar indexes: IndexesOperations operations
    :vartype indexes: azure.search.documents.aio.operations_async.IndexesOperations
    :param endpoint: The endpoint URL of the search service.
    :type endpoint: str
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        endpoint: str,
        **kwargs: Any
    ) -> None:
        base_url = '{endpoint}'
        self._config = SearchServiceClientConfiguration(endpoint, **kwargs)
        self._client = AsyncPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.data_sources = DataSourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.indexers = IndexersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.skillsets = SkillsetsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.synonym_maps = SynonymMapsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.indexes = IndexesOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "SearchServiceClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
