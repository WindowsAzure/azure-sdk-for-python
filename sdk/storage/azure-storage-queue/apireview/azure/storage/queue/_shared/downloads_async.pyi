# Stubs for azure.storage.queue._shared.downloads_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from .downloads import process_range_and_offset
from .encryption import decrypt_blob
from .request_handlers import validate_and_format_range_headers
from .response_handlers import parse_length_from_content_range, process_storage_error
from typing import Any, Optional

async def process_content(data: Any, start_offset: Any, end_offset: Any, encryption: Any): ...

class _AsyncChunkDownloader:
    service: Any = ...
    chunk_size: Any = ...
    total_size: Any = ...
    start_index: Any = ...
    end_index: Any = ...
    stream: Any = ...
    stream_lock: Any = ...
    progress_lock: Any = ...
    stream_start: Any = ...
    progress_total: Any = ...
    encryption_options: Any = ...
    validate_content: Any = ...
    request_options: Any = ...
    def __init__(self, service: Optional[Any] = ..., total_size: Optional[Any] = ..., chunk_size: Optional[Any] = ..., current_progress: Optional[Any] = ..., start_range: Optional[Any] = ..., end_range: Optional[Any] = ..., stream: Optional[Any] = ..., parallel: Optional[Any] = ..., validate_content: Optional[Any] = ..., encryption_options: Optional[Any] = ..., **kwargs: Any) -> None: ...
    def get_chunk_offsets(self) -> None: ...
    async def process_chunk(self, chunk_start: Any) -> None: ...
    async def yield_chunk(self, chunk_start: Any): ...

class StorageStreamDownloader:
    service: Any = ...
    config: Any = ...
    offset: Any = ...
    length: Any = ...
    validate_content: Any = ...
    encryption_options: Any = ...
    request_options: Any = ...
    location_mode: Any = ...
    first_get_size: Any = ...
    download_size: Any = ...
    file_size: Any = ...
    response: Any = ...
    properties: Any = ...
    def __init__(self, service: Optional[Any] = ..., config: Optional[Any] = ..., offset: Optional[Any] = ..., length: Optional[Any] = ..., validate_content: Optional[Any] = ..., encryption_options: Optional[Any] = ..., **kwargs: Any) -> None: ...
    def __len__(self): ...
    def __iter__(self) -> None: ...
    def __aiter__(self): ...
    async def __anext__(self): ...
    async def setup(self, extra_properties: Optional[Any] = ...) -> None: ...
    async def content_as_bytes(self, max_connections: int = ...): ...
    async def content_as_text(self, max_connections: int = ..., encoding: str = ...): ...
    async def download_to_stream(self, stream: Any, max_connections: int = ...): ...
