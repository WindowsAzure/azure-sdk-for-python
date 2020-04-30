# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING

from azure.core.tracing.decorator import distributed_trace

from ._generated import SearchServiceClient as _SearchServiceClient
from .._headers_mixin import HeadersMixin
from .._version import SDK_MONIKER

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from ._generated.models import Indexer, IndexerExecutionInfo
    from typing import Any, Dict, Optional, Sequence
    from azure.core.credentials import AzureKeyCredential


class SearchIndexersClient(HeadersMixin):
    """A client to interact with Azure search service Indexers.

    This class is not normally instantiated directly, instead use
    `get_indexers_client()` from a `SearchServiceClient`

    """

    _ODATA_ACCEPT = "application/json;odata.metadata=minimal"  # type: str

    def __init__(self, endpoint, credential, **kwargs):
        # type: (str, AzureKeyCredential, **Any) -> None

        self._endpoint = endpoint  # type: str
        self._credential = credential  # type: AzureKeyCredential
        self._client = _SearchServiceClient(
            endpoint=endpoint, sdk_moniker=SDK_MONIKER, **kwargs
        )  # type: _SearchServiceClient

    def __enter__(self):
        # type: () -> SearchIndexersClient
        self._client.__enter__()  # pylint:disable=no-member
        return self

    def __exit__(self, *args):
        # type: (*Any) -> None
        return self._client.__exit__(*args)  # pylint:disable=no-member

    def close(self):
        # type: () -> None
        """Close the :class:`~azure.search.documents.SearchIndexersClient` session.

        """
        return self._client.close()

    @distributed_trace
    def create_indexer(self, indexer, **kwargs):
        # type: (Indexer, **Any) -> Dict[str, Any]
        """Creates a new Indexers.

        :param indexer: The definition of the indexer to create.
        :type indexer: ~search.models.Indexer
        :return: The created Indexer
        :rtype: dict

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_indexer_operations.py
                :start-after: [START create_indexer]
                :end-before: [END create_indexer]
                :language: python
                :dedent: 4
                :caption: Create an Indexer
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = self._client.indexers.create(indexer, **kwargs)
        return result

    @distributed_trace
    def create_or_update_indexer(self, indexer, name=None, **kwargs):
        # type: (Indexer, Optional[str], **Any) -> Dict[str, Any]
        """Creates a new indexer or updates a indexer if it already exists.

        :param name: The name of the indexer to create or update.
        :type name: str
        :param indexer: The definition of the indexer to create or update.
        :type indexer: ~search.models.Indexer
        :return: The created Indexer
        :rtype: dict
        """
        # TODO: access_condition
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))

        if not name:
            name = indexer.name
        result = self._client.indexers.create_or_update(name, indexer, **kwargs)
        return result

    @distributed_trace
    def get_indexer(self, name, **kwargs):
        # type: (str, **Any) -> Dict[str, Any]
        """Retrieves a indexer definition.

        :param name: The name of the indexer to retrieve.
        :type name: str
        :return: The Indexer that is fetched.
        :rtype: dict

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_indexer_operations.py
                :start-after: [START get_indexer]
                :end-before: [END get_indexer]
                :language: python
                :dedent: 4
                :caption: Retrieve an Indexer
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = self._client.indexers.get(name, **kwargs)
        return result

    @distributed_trace
    def get_indexers(self, **kwargs):
        # type: (**Any) -> Sequence[Indexer]
        """Lists all indexers available for a search service.

        :return: List of all the Indexers.
        :rtype: `list[dict]`

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_indexer_operations.py
                :start-after: [START list_indexer]
                :end-before: [END list_indexer]
                :language: python
                :dedent: 4
                :caption: List all the Indexers
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        result = self._client.indexers.list(**kwargs)
        return result.indexers

    @distributed_trace
    def delete_indexer(self, indexer, **kwargs):
        # type: (Union[str, Indexer], **Any) -> None
        """Deletes an indexer. To use only_if_unchanged, the Indexer model
        must be provided instead of the name. It is enough to provide
        the name of the indexer to delete unconditionally.

        :param name: The name of the indexer to delete.
        :type name: str
        :keyword only_if_unchanged: If set to true, the operation is performed only if the
        e_tag on the server matches the e_tag value of the passed synonym_map.
        :type only_if_unchanged: bool

        :return: None
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_indexer_operations.py
                :start-after: [START delete_indexer]
                :end-before: [END delete_indexer]
                :language: python
                :dedent: 4
                :caption: Delete an Indexer
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        access_condition = None
        try:
            name = indexer.name
            # TODO: update the placeholder
            access_condition = None
        except AttributeError:
            name = indexer
        self._client.indexers.delete(name, access_condition=access_condition, **kwargs)

    @distributed_trace
    def run_indexer(self, name, **kwargs):
        # type: (str, **Any) -> None
        """Run an indexer.

        :param name: The name of the indexer to run.
        :type name: str

        :return: None
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_indexer_operations.py
                :start-after: [START run_indexer]
                :end-before: [END run_indexer]
                :language: python
                :dedent: 4
                :caption: Run an Indexer
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        self._client.indexers.run(name, **kwargs)

    @distributed_trace
    def reset_indexer(self, name, **kwargs):
        # type: (str, **Any) -> None
        """Resets the change tracking state associated with an indexer.

        :param name: The name of the indexer to reset.
        :type name: str

        :return: None
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_indexer_operations.py
                :start-after: [START reset_indexer]
                :end-before: [END reset_indexer]
                :language: python
                :dedent: 4
                :caption: Reset an Indexer's change tracking state
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        self._client.indexers.reset(name, **kwargs)

    @distributed_trace
    def get_indexer_status(self, name, **kwargs):
        # type: (str, **Any) -> IndexerExecutionInfo
        """Get the status of the indexer.

        :param name: The name of the indexer to fetch the status.
        :type name: str

        :return: IndexerExecutionInfo
        :rtype: IndexerExecutionInfo

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_indexer_operations.py
                :start-after: [START get_indexer_status]
                :end-before: [END get_indexer_status]
                :language: python
                :dedent: 4
                :caption: Get an Indexer's status
        """
        kwargs["headers"] = self._merge_client_headers(kwargs.get("headers"))
        return self._client.indexers.get_status(name, **kwargs)
