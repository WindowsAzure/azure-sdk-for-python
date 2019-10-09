# Stubs for azure.storage.file._shared.uploads (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from .encryption import get_blob_encryptor_and_padder
from .request_handlers import get_length
from .response_handlers import return_response_headers
from io import IOBase
from typing import Any, Optional

def upload_data_chunks(service: Optional[Any] = ..., uploader_class: Optional[Any] = ..., total_size: Optional[Any] = ..., chunk_size: Optional[Any] = ..., max_connections: Optional[Any] = ..., stream: Optional[Any] = ..., validate_content: Optional[Any] = ..., encryption_options: Optional[Any] = ..., **kwargs: Any): ...
def upload_substream_blocks(service: Optional[Any] = ..., uploader_class: Optional[Any] = ..., total_size: Optional[Any] = ..., chunk_size: Optional[Any] = ..., max_connections: Optional[Any] = ..., stream: Optional[Any] = ..., **kwargs: Any): ...

class _ChunkUploader:
    service: Any = ...
    total_size: Any = ...
    chunk_size: Any = ...
    stream: Any = ...
    parallel: Any = ...
    stream_start: Any = ...
    stream_lock: Any = ...
    progress_total: int = ...
    progress_lock: Any = ...
    encryptor: Any = ...
    padder: Any = ...
    response_headers: Any = ...
    etag: Any = ...
    last_modified: Any = ...
    request_options: Any = ...
    def __init__(self, service: Any, total_size: Any, chunk_size: Any, stream: Any, parallel: Any, encryptor: Optional[Any] = ..., padder: Optional[Any] = ..., **kwargs: Any) -> None: ...
    def get_chunk_streams(self) -> None: ...
    def process_chunk(self, chunk_data: Any): ...
    def get_substream_blocks(self) -> None: ...
    def process_substream_block(self, block_data: Any): ...
    def set_response_properties(self, resp: Any) -> None: ...

class BlockBlobChunkUploader(_ChunkUploader):
    current_length: Any = ...
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

class PageBlobChunkUploader(_ChunkUploader): ...

class AppendBlobChunkUploader(_ChunkUploader):
    current_length: Any = ...
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

class FileChunkUploader(_ChunkUploader): ...

class SubStream(IOBase):
    def __init__(self, wrapped_stream: Any, stream_begin_index: Any, length: Any, lockObj: Any) -> None: ...
    def __len__(self): ...
    def close(self) -> None: ...
    def fileno(self): ...
    def flush(self) -> None: ...
    def read(self, n: Any): ...
    def readable(self): ...
    def readinto(self, b: Any) -> None: ...
    def seek(self, offset: Any, whence: int = ...): ...
    def seekable(self): ...
    def tell(self): ...
    def write(self) -> None: ...
    def writelines(self) -> None: ...
    def writeable(self): ...

class IterStreamer:
    generator: Any = ...
    iterator: Any = ...
    leftover: bytes = ...
    encoding: Any = ...
    def __init__(self, generator: Any, encoding: str = ...) -> None: ...
    def __len__(self): ...
    def __iter__(self): ...
    def seekable(self): ...
    def next(self): ...
    def tell(self, *args: Any, **kwargs: Any) -> None: ...
    def seek(self, *args: Any, **kwargs: Any) -> None: ...
    def read(self, size: Any): ...
