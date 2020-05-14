# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING

from azure.core.tracing.decorator_async import distributed_trace_async

from .._generated.aio import SearchServiceClient as _SearchServiceClient
from .._search_service_client_base import SearchServiceClientBase
from ..._version import SDK_MONIKER
from ._datasources_client import SearchDataSourcesClient
from ._indexes_client import SearchIndexesClient
from ._indexers_client import SearchIndexersClient
from ._skillsets_client import SearchSkillsetsClient
from ._synonym_maps_client import SearchSynonymMapsClient

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from typing import Any, Dict, List, Optional, Sequence
    from azure.core.credentials import AzureKeyCredential


class SearchServiceClient(SearchServiceClientBase):  # pylint: disable=too-many-public-methods
    """A client to interact with an existing Azure search service.

    :param endpoint: The URL endpoint of an Azure search service
    :type endpoint: str
    :param credential: A credential to authorize search client requests
    :type credential: ~azure.core.credentials import AzureKeyCredential

    .. admonition:: Example:

        .. literalinclude:: ../samples/async_samples/sample_authentication_async.py
            :start-after: [START create_search_service_with_key_async]
            :end-before: [END create_search_service_with_key_async]
            :language: python
            :dedent: 4
            :caption: Creating the SearchServiceClient with an API key.
    """

    _ODATA_ACCEPT = "application/json;odata.metadata=minimal"  # type: str

    def __init__(self, endpoint, credential, **kwargs):
        # type: (str, AzureKeyCredential, **Any) -> None

        super().__init__(endpoint, credential, **kwargs)
        self._client = _SearchServiceClient(
            endpoint=endpoint, sdk_moniker=SDK_MONIKER, **kwargs
        )  # type: _SearchServiceClient

        self._indexes_client = SearchIndexesClient(endpoint, credential, **kwargs)

        self._synonym_maps_client = SearchSynonymMapsClient(
            endpoint, credential, **kwargs
        )

        self._skillsets_client = SearchSkillsetsClient(endpoint, credential, **kwargs)

        self._datasources_client = SearchDataSourcesClient(
            endpoint, credential, **kwargs
        )

        self._indexers_client = SearchIndexersClient(endpoint, credential, **kwargs)

    async def __aenter__(self):
        # type: () -> SearchServiceClient
        await self._client.__aenter__()  # pylint:disable=no-member
        return self

    async def __aexit__(self, *args):
        # type: (*Any) -> None
        return await self._client.__aexit__(*args)  # pylint:disable=no-member

    async def close(self):
        # type: () -> None
        """Close the :class:`~azure.search.documents.aio.SearchServiceClient` session.

        """
        return await self._client.close()

    @distributed_trace_async
    async def get_service_statistics(self, **kwargs):
        # type: (**Any) -> dict
        """Get service level statistics for a search service.

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = await self._client.get_service_statistics(**kwargs)
        return result.as_dict()

    def get_indexes_client(self):
        # type: () -> SearchIndexesClient
        """Return a client to perform operations on Search Indexes.

        :return: The Search Indexes client
        :rtype: SearchIndexesClient
        """
        return self._indexes_client

    def get_synonym_maps_client(self):
        # type: () -> SearchSynonymMapsClient
        """Return a client to perform operations on Synonym Maps.

        :return: The Synonym Maps client
        :rtype: SearchSynonymMapsClient
        """
        return self._synonym_maps_client

    def get_skillsets_client(self) -> SearchSkillsetsClient:
        """Return a client to perform operations on Skillsets.

        :return: The Skillsets client
        :rtype: SearchSkillsetsClient
        """
        return self._skillsets_client

    def get_datasources_client(self) -> SearchDataSourcesClient:
        """Return a client to perform operations on Data Sources.

        :return: The Data Sources client
        :rtype: SearchDataSourcesClient
        """
        return self._datasources_client

    def get_indexers_client(self):
        # type: () -> SearchIndexersClient
        """Return a client to perform operations on Data Sources.

        :return: The Data Sources client
        :rtype: SearchDataSourcesClient
        """
        return self._indexers_client
