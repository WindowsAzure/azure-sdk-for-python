# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING

from azure.core.tracing.decorator_async import distributed_trace_async

from .._generated.aio import SearchServiceClient as _SearchServiceClient
from .._generated.models import SynonymMap
from .._utils import listize_synonyms
from ..._headers_mixin import HeadersMixin
from ..._version import SDK_MONIKER

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from .._generated.models import Skill
    from typing import Any, Dict, List, Sequence
    from azure.core.credentials import AzureKeyCredential


class SearchSynonymMapsClient(HeadersMixin):
    """A client to interact with Azure search service Synonym Maps.

    This class is not normally instantiated directly, instead use
    `get_synonym_maps_client()` from a `SearchServiceClient`

    """

    _ODATA_ACCEPT = "application/json;odata.metadata=minimal"  # type: str

    def __init__(self, endpoint, credential, **kwargs):
        # type: (str, AzureKeyCredential, **Any) -> None

        self._endpoint = endpoint  # type: str
        self._credential = credential  # type: AzureKeyCredential
        self._client = _SearchServiceClient(
            endpoint=endpoint, sdk_moniker=SDK_MONIKER, **kwargs
        )  # type: _SearchServiceClient

    async def __aenter__(self):
        # type: () -> SearchSynonymMapsClient
        await self._client.__aenter__()  # pylint:disable=no-member
        return self

    async def __aexit__(self, *args):
        # type: (*Any) -> None
        return await self._client.__aexit__(*args)  # pylint:disable=no-member

    async def close(self):
        # type: () -> None
        """Close the :class:`~azure.search.documents.DataSourcesClient` session.

        """
        return await self._client.close()

    @distributed_trace_async
    async def get_synonym_maps(self, **kwargs):
        # type: (**Any) -> List[Dict[Any, Any]]
        """List the Synonym Maps in an Azure Search service.

        :return: List of synonym maps
        :rtype: list[dict]
        :raises: ~azure.core.exceptions.HttpResponseError

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_synonym_map_operations_async.py
                :start-after: [START get_synonym_maps_async]
                :end-before: [END get_synonym_maps_async]
                :language: python
                :dedent: 4
                :caption: List Synonym Maps

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = await self._client.synonym_maps.list(**kwargs)
        return [listize_synonyms(x) for x in result.as_dict()["synonym_maps"]]

    @distributed_trace_async
    async def get_synonym_map(self, name, **kwargs):
        # type: (str, **Any) -> dict
        """Retrieve a named Synonym Map in an Azure Search service

        :param name: The name of the Synonym Map to get
        :type name: str
        :return: The retrieved Synonym Map
        :rtype: dict
        :raises: :class:`~azure.core.exceptions.ResourceNotFoundError`

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_synonym_map_operations_async.py
                :start-after: [START get_synonym_map_async]
                :end-before: [END get_synonym_map_async]
                :language: python
                :dedent: 4
                :caption: Get a Synonym Map

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = await self._client.synonym_maps.get(name, **kwargs)
        return listize_synonyms(result.as_dict())

    @distributed_trace_async
    async def delete_synonym_map(self, name, **kwargs):
        # type: (str, **Any) -> None
        """Delete a named Synonym Map in an Azure Search service

        :param name: The name of the Synonym Map to delete
        :type name: str

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_synonym_map_operations_async.py
                :start-after: [START delete_synonym_map_async]
                :end-before: [END delete_synonym_map_async]
                :language: python
                :dedent: 4
                :caption: Delete a Synonym Map

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        await self._client.synonym_maps.delete(name, **kwargs)

    @distributed_trace_async
    async def create_synonym_map(self, name, synonyms, **kwargs):
        # type: (str, Sequence[str], **Any) -> dict
        """Create a new Synonym Map in an Azure Search service

        :param name: The name of the Synonym Map to create
        :type name: str
        :param synonyms: A list of synonyms in SOLR format
        :type synonyms: List[str]
        :return: The created Synonym Map
        :rtype: dict

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_synonym_map_operations_async.py
                :start-after: [START create_synonym_map_async]
                :end-before: [END create_synonym_map_async]
                :language: python
                :dedent: 4
                :caption: Create a Synonym Map

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        solr_format_synonyms = "\n".join(synonyms)
        synonym_map = SynonymMap(name=name, synonyms=solr_format_synonyms)
        result = await self._client.synonym_maps.create(synonym_map, **kwargs)
        return listize_synonyms(result.as_dict())

    @distributed_trace_async
    async def create_or_update_synonym_map(self, name, synonyms, **kwargs):
        # type: (str, Sequence[str], **Any) -> dict
        """Create a new Synonym Map in an Azure Search service, or update an
        existing one.

        :param name: The name of the Synonym Map to create or update
        :type name: str
        :param synonyms: A list of synonyms in SOLR format
        :type synonyms: List[str]
        :return: The created or updated Synonym Map
        :rtype: dict

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        solr_format_synonyms = "\n".join(synonyms)
        synonym_map = SynonymMap(name=name, synonyms=solr_format_synonyms)
        result = await self._client.synonym_maps.create_or_update(
            name, synonym_map, **kwargs
        )
        return listize_synonyms(result.as_dict())
