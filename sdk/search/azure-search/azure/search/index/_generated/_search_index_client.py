# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6198, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any

from azure.core import PipelineClient
from msrest import Deserializer, Serializer

from ._configuration import SearchIndexClientConfiguration
from .operations import DocumentsOperations
from . import models


class SearchIndexClient(object):
    """Client that can be used to query an index and upload, merge, or delete documents.

    :ivar documents: DocumentsOperations operations
    :vartype documents: search_index_client.operations.DocumentsOperations
    :param search_service_name: The name of the search service.
    :type search_service_name: str
    :param search_dns_suffix: The DNS suffix of the search service. The default is search.windows.net.
    :type search_dns_suffix: str
    :param index_name: The name of the index.
    :type index_name: str
    """

    def __init__(
        self,
        search_service_name,  # type: str
        search_dns_suffix,  # type: str
        index_name,  # type: str
        base_url=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        base_url = 'https://{searchServiceName}.{searchDnsSuffix}/indexes(\'{indexName}\')'
        self._config = SearchIndexClientConfiguration(search_service_name, search_dns_suffix, index_name, **kwargs)
        self._client = PipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.documents = DocumentsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> SearchIndexClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
