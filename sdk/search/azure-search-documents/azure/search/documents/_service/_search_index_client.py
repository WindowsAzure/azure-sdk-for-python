# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING

from azure.core import MatchConditions
from azure.core.tracing.decorator import distributed_trace
from azure.core.paging import ItemPaged

from ._generated import SearchServiceClient as _SearchServiceClient
from ._generated.models import SynonymMap
from ._utils import (
    delistize_flags_for_index,
    listize_flags_for_index,
    listize_synonyms,
    get_access_conditions,
    normalize_endpoint,
)
from .._headers_mixin import HeadersMixin
from .._version import SDK_MONIKER
from .. import SearchClient

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from typing import Any, Dict, List, Sequence, Union, Optional
    from azure.core.credentials import AzureKeyCredential


class SearchIndexClient(HeadersMixin):
    """A client to interact with Azure search service index.

    """

    _ODATA_ACCEPT = "application/json;odata.metadata=minimal"  # type: str

    def __init__(self, endpoint, credential, **kwargs):
        # type: (str, AzureKeyCredential, **Any) -> None

        self._endpoint = normalize_endpoint(endpoint)  # type: str
        self._credential = credential  # type: AzureKeyCredential
        self._client = _SearchServiceClient(
            endpoint=endpoint, sdk_moniker=SDK_MONIKER, **kwargs
        )  # type: _SearchServiceClient

    def __enter__(self):
        # type: () -> SearchIndexClient
        self._client.__enter__()  # pylint:disable=no-member
        return self

    def __exit__(self, *args):
        # type: (*Any) -> None
        return self._client.__exit__(*args)  # pylint:disable=no-member

    def close(self):
        # type: () -> None
        """Close the :class:`~azure.search.documents.SearchIndexClient` session.

        """
        return self._client.close()

    @distributed_trace
    def get_search_client(self, index_name, **kwargs):
        # type: (str, dict) -> SearchClient
        """Return a client to perform operations on Search

        :param index_name: The name of the Search Index
        :type index_name: str
        :rtype: ~azure.search.documents.SearchClient

        """
        return SearchClient(self._endpoint, index_name, self._credential, **kwargs)

    @distributed_trace
    def list_indexes(self, **kwargs):
        # type: (**Any) -> ItemPaged[SearchIndex]
        """List the indexes in an Azure Search service.

        :return: List of indexes
        :rtype: list[~azure.search.documents.SearchIndex]
        :raises: ~azure.core.exceptions.HttpResponseError

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))

        def get_next(_token):
            return self._client.indexes.list(**kwargs)

        def extract_data(response):
            return None, [listize_flags_for_index(x) for x in response.indexes]

        return ItemPaged(get_next=get_next, extract_data=extract_data)

    @distributed_trace
    def get_index(self, index_name, **kwargs):
        # type: (str, **Any) -> SearchIndex
        """

        :param index_name: The name of the index to retrieve.
        :type index_name: str
        :return: SearchIndex object
        :rtype: ~azure.search.documents.SearchIndex
        :raises: ~azure.core.exceptions.HttpResponseError

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_index_crud_operations.py
                :start-after: [START get_index]
                :end-before: [END get_index]
                :language: python
                :dedent: 4
                :caption: Get an index.
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = self._client.indexes.get(index_name, **kwargs)
        return listize_flags_for_index(result)

    @distributed_trace
    def get_index_statistics(self, index_name, **kwargs):
        # type: (str, **Any) -> dict
        """Returns statistics for the given index, including a document count
        and storage usage.

        :param index_name: The name of the index to retrieve.
        :type index_name: str
        :return: Statistics for the given index, including a document count and storage usage.
        :rtype: ~azure.search.documents.GetIndexStatisticsResult
        :raises: ~azure.core.exceptions.HttpResponseError

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = self._client.indexes.get_statistics(index_name, **kwargs)
        return result.as_dict()

    @distributed_trace
    def delete_index(self, index, **kwargs):
        # type: (Union[str, SearchIndex], **Any) -> None
        """Deletes a search index and all the documents it contains. The model must be
        provided instead of the name to use the access conditions.

        :param index: The index to retrieve.
        :type index: str or ~search.models.SearchIndex
        :keyword match_condition: The match condition to use upon the etag
        :type match_condition: ~azure.core.MatchConditions
        :raises: ~azure.core.exceptions.HttpResponseError

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_index_crud_operations.py
                :start-after: [START delete_index]
                :end-before: [END delete_index]
                :language: python
                :dedent: 4
                :caption: Delete an index.
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        error_map, access_condition = get_access_conditions(
            index, kwargs.pop("match_condition", MatchConditions.Unconditionally)
        )
        kwargs.update(access_condition)
        try:
            index_name = index.name
        except AttributeError:
            index_name = index
        self._client.indexes.delete(
            index_name=index_name, error_map=error_map, **kwargs
        )

    @distributed_trace
    def create_index(self, index, **kwargs):
        # type: (SearchIndex, **Any) -> SearchIndex
        """Creates a new search index.

        :param index: The index object.
        :type index: ~azure.search.documents.SearchIndex
        :return: The index created
        :rtype: ~azure.search.documents.SearchIndex
        :raises: ~azure.core.exceptions.HttpResponseError

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_index_crud_operations.py
                :start-after: [START create_index]
                :end-before: [END create_index]
                :language: python
                :dedent: 4
                :caption: Creating a new index.
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        patched_index = delistize_flags_for_index(index)
        result = self._client.indexes.create(patched_index, **kwargs)
        return result

    @distributed_trace
    def create_or_update_index(
        self, index_name, index, allow_index_downtime=None, **kwargs
    ):
        # type: (str, SearchIndex, bool, **Any) -> SearchIndex
        """Creates a new search index or updates an index if it already exists.

        :param index_name: The name of the index.
        :type index_name: str
        :param index: The index object.
        :type index: ~azure.search.documents.SearchIndex
        :param allow_index_downtime: Allows new analyzers, tokenizers, token filters, or char filters
         to be added to an index by taking the index offline for at least a few seconds. This
         temporarily causes indexing and query requests to fail. Performance and write availability of
         the index can be impaired for several minutes after the index is updated, or longer for very
         large indexes.
        :type allow_index_downtime: bool
        :keyword match_condition: The match condition to use upon the etag
        :type match_condition: ~azure.core.MatchConditions
        :return: The index created or updated
        :rtype: :class:`~azure.search.documents.SearchIndex`
        :raises: :class:`~azure.core.exceptions.ResourceNotFoundError`, \
        :class:`~azure.core.exceptions.ResourceModifiedError`, \
        :class:`~azure.core.exceptions.ResourceNotModifiedError`, \
        :class:`~azure.core.exceptions.ResourceNotFoundError`, \
        :class:`~azure.core.exceptions.ResourceExistsError`

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_index_crud_operations.py
                :start-after: [START update_index]
                :end-before: [END update_index]
                :language: python
                :dedent: 4
                :caption: Update an index.
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        error_map, access_condition = get_access_conditions(
            index, kwargs.pop("match_condition", MatchConditions.Unconditionally)
        )
        kwargs.update(access_condition)
        patched_index = delistize_flags_for_index(index)
        result = self._client.indexes.create_or_update(
            index_name=index_name,
            index=patched_index,
            allow_index_downtime=allow_index_downtime,
            error_map=error_map,
            **kwargs
        )
        return result

    @distributed_trace
    def analyze_text(self, index_name, analyze_request, **kwargs):
        # type: (str, AnalyzeRequest, **Any) -> AnalyzeResult
        """Shows how an analyzer breaks text into tokens.

        :param index_name: The name of the index for which to test an analyzer.
        :type index_name: str
        :param analyze_request: The text and analyzer or analysis components to test.
        :type analyze_request: ~azure.search.documents.AnalyzeRequest
        :return: AnalyzeResult
        :rtype: ~azure.search.documents.AnalyzeResult
        :raises: ~azure.core.exceptions.HttpResponseError

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_analyze_text.py
                :start-after: [START simple_analyze_text]
                :end-before: [END simple_analyze_text]
                :language: python
                :dedent: 4
                :caption: Analyze text
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = self._client.indexes.analyze(
            index_name=index_name, request=analyze_request, **kwargs
        )
        return result

    @distributed_trace
    def get_synonym_maps(self, **kwargs):
        # type: (**Any) -> List[Dict[Any, Any]]
        """List the Synonym Maps in an Azure Search service.

        :return: List of synonym maps
        :rtype: list[dict]
        :raises: ~azure.core.exceptions.HttpResponseError

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_synonym_map_operations.py
                :start-after: [START get_synonym_maps]
                :end-before: [END get_synonym_maps]
                :language: python
                :dedent: 4
                :caption: List Synonym Maps

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = self._client.synonym_maps.list(**kwargs)
        return [listize_synonyms(x) for x in result.as_dict()["synonym_maps"]]

    @distributed_trace
    def get_synonym_map(self, name, **kwargs):
        # type: (str, **Any) -> dict
        """Retrieve a named Synonym Map in an Azure Search service

        :param name: The name of the Synonym Map to get
        :type name: str
        :return: The retrieved Synonym Map
        :rtype: dict
        :raises: :class:`~azure.core.exceptions.ResourceNotFoundError`

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_synonym_map_operations.py
                :start-after: [START get_synonym_map]
                :end-before: [END get_synonym_map]
                :language: python
                :dedent: 4
                :caption: Get a Synonym Map

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = self._client.synonym_maps.get(name, **kwargs)
        return listize_synonyms(result.as_dict())

    @distributed_trace
    def delete_synonym_map(self, synonym_map, **kwargs):
        # type: (Union[str, SynonymMap], **Any) -> None
        """Delete a named Synonym Map in an Azure Search service. To use access conditions,
        the SynonymMap model must be provided instead of the name. It is enough to provide
        the name of the synonym map to delete unconditionally.

        :param name: The Synonym Map to delete
        :type name: str or ~search.models.SynonymMap
        :keyword match_condition: The match condition to use upon the etag
        :type match_condition: ~azure.core.MatchConditions
        :return: None
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_synonym_map_operations.py
                :start-after: [START delete_synonym_map]
                :end-before: [END delete_synonym_map]
                :language: python
                :dedent: 4
                :caption: Delete a Synonym Map

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        error_map, access_condition = get_access_conditions(
            synonym_map, kwargs.pop("match_condition", MatchConditions.Unconditionally)
        )
        kwargs.update(access_condition)
        try:
            name = synonym_map.name
        except AttributeError:
            name = synonym_map
        self._client.synonym_maps.delete(
            synonym_map_name=name, error_map=error_map, **kwargs
        )

    @distributed_trace
    def create_synonym_map(self, name, synonyms, **kwargs):
        # type: (str, Sequence[str], **Any) -> dict
        """Create a new Synonym Map in an Azure Search service

        :param name: The name of the Synonym Map to create
        :type name: str
        :param synonyms: The list of synonyms in SOLR format
        :type synonyms: List[str]
        :return: The created Synonym Map
        :rtype: dict

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_synonym_map_operations.py
                :start-after: [START create_synonym_map]
                :end-before: [END create_synonym_map]
                :language: python
                :dedent: 4
                :caption: Create a Synonym Map

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        solr_format_synonyms = "\n".join(synonyms)
        synonym_map = SynonymMap(name=name, synonyms=solr_format_synonyms)
        result = self._client.synonym_maps.create(synonym_map, **kwargs)
        return listize_synonyms(result.as_dict())

    @distributed_trace
    def create_or_update_synonym_map(self, synonym_map, synonyms=None, **kwargs):
        # type: (Union[str, SynonymMap], Optional[Sequence[str]], **Any) -> dict
        """Create a new Synonym Map in an Azure Search service, or update an
        existing one.

        :param synonym_map: The name of the Synonym Map to create or update
        :type synonym_map: str or ~azure.search.documents.SynonymMap
        :param synonyms: A list of synonyms in SOLR format
        :type synonyms: List[str]
        :keyword match_condition: The match condition to use upon the etag
        :type match_condition: ~azure.core.MatchConditions
        :return: The created or updated Synonym Map
        :rtype: dict

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        error_map, access_condition = get_access_conditions(
            synonym_map, kwargs.pop("match_condition", MatchConditions.Unconditionally)
        )
        kwargs.update(access_condition)
        try:
            name = synonym_map.name
            if synonyms:
                synonym_map.synonyms = "\n".join(synonyms)
        except AttributeError:
            name = synonym_map
            solr_format_synonyms = "\n".join(synonyms)
            synonym_map = SynonymMap(name=name, synonyms=solr_format_synonyms)
        result = self._client.synonym_maps.create_or_update(
            synonym_map_name=name,
            synonym_map=synonym_map,
            error_map=error_map,
            **kwargs
        )
        return listize_synonyms(result.as_dict())

    @distributed_trace
    def get_service_statistics(self, **kwargs):
        # type: (**Any) -> dict
        """Get service level statistics for a search service.

        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = self._client.get_service_statistics(**kwargs)
        return result.as_dict()
