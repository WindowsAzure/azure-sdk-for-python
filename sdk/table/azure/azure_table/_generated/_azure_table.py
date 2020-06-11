# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6282, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.core import PipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

from ._configuration import AzureTableConfiguration
from .operations import TableOperations
from .operations import ServiceOperations
from azure.azure_table._generated import models



class AzureTable(object):
    """AzureTable.

    :ivar table: TableOperations operations
    :vartype table: azure_table.operations.TableOperations
    :ivar service: ServiceOperations operations
    :vartype service: azure_table.operations.ServiceOperations
    :param url: The URL of the service account or table that is the targe of the desired operation.
    :type url: str
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        url,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        base_url = '{url}'
        self._config = AzureTableConfiguration(url, **kwargs)
        self._client = PipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.table = TableOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.service = ServiceOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> AzureTable
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
