# Stubs for azure.storage.blob.aio._models (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from .._generated.models import BlobItem, StorageErrorException
from .._models import BlobProperties, ContainerProperties
from .._shared.models import DictMixin
from .._shared.response_handlers import process_storage_error, return_context_and_deserialized
from azure.core.async_paging import AsyncItemPaged, AsyncPageIterator
from typing import Any, Optional

class ContainerPropertiesPaged(AsyncPageIterator):
    service_endpoint: Any = ...
    prefix: Any = ...
    marker: Any = ...
    results_per_page: Any = ...
    location_mode: Any = ...
    current_page: Any = ...
    def __init__(self, command: Any, prefix: Optional[Any] = ..., results_per_page: Optional[Any] = ..., continuation_token: Optional[Any] = ...) -> None: ...

class BlobPropertiesPaged(AsyncPageIterator):
    service_endpoint: Any = ...
    prefix: Any = ...
    marker: Any = ...
    results_per_page: Any = ...
    container: Any = ...
    delimiter: Any = ...
    current_page: Any = ...
    location_mode: Any = ...
    def __init__(self, command: Any, container: Optional[Any] = ..., prefix: Optional[Any] = ..., results_per_page: Optional[Any] = ..., continuation_token: Optional[Any] = ..., delimiter: Optional[Any] = ..., location_mode: Optional[Any] = ...) -> None: ...

class BlobPrefix(AsyncItemPaged, DictMixin):
    name: Any = ...
    prefix: Any = ...
    results_per_page: Any = ...
    container: Any = ...
    delimiter: Any = ...
    location_mode: Any = ...
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

class BlobPrefixPaged(BlobPropertiesPaged):
    name: Any = ...
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
