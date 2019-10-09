# Stubs for azure.storage.file.file_client (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ._deserialize import deserialize_file_properties, deserialize_file_stream
from ._generated import AzureFileStorage
from ._generated.models import FileHTTPHeaders, HandleItem, StorageErrorException
from ._generated.version import VERSION
from ._parser import _datetime_to_str, _get_file_permission
from ._polling import CloseHandles
from ._shared.base_client import StorageAccountHostsMixin, parse_connection_str, parse_query
from ._shared.downloads import StorageStreamDownloader
from ._shared.parser import _str
from ._shared.request_handlers import add_metadata_headers, get_length
from ._shared.response_handlers import process_storage_error, return_response_headers
from ._shared.uploads import FileChunkUploader, IterStreamer, upload_data_chunks
from ._shared_access_signature import FileSharedAccessSignature
from .models import ContentSettings, FilePermissions, FileProperties, HandlesPaged, NTFSAttributes, ShareProperties
from azure.core.paging import ItemPaged
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Union

class FileClient(StorageAccountHostsMixin):
    snapshot: Any = ...
    share_name: Any = ...
    file_path: Any = ...
    file_name: Any = ...
    directory_path: Any = ...
    def __init__(self, file_url: str, share: Optional[Union[str, ShareProperties]]=..., file_path: Optional[str]=..., snapshot: Optional[Union[str, Dict[str, Any]]]=..., credential: Optional[Any]=..., **kwargs: Any) -> None: ...
    @classmethod
    def from_connection_string(cls: Any, conn_str: str, share: Optional[Union[str, ShareProperties]]=..., file_path: Optional[str]=..., snapshot: Optional[Union[str, Dict[str, Any]]]=..., credential: Optional[Any]=..., **kwargs: Any) -> FileClient: ...
    def generate_shared_access_signature(self, permission: Optional[Union[FilePermissions, str]]=..., expiry: Optional[Union[datetime, str]]=..., start: Optional[Union[datetime, str]]=..., policy_id: Optional[str]=..., ip: Optional[str]=..., protocol: Optional[str]=..., cache_control: Optional[str]=..., content_disposition: Optional[str]=..., content_encoding: Optional[str]=..., content_language: Optional[str]=..., content_type: Optional[str]=...) -> str: ...
    def create_file(self, size: int, content_settings: Optional[ContentSettings]=..., metadata: Optional[Dict[str, str]]=..., file_attributes: Union[str, NTFSAttributes]=..., file_creation_time: Union[str, datetime]=..., file_last_write_time: Union[str, datetime]=..., file_permission: Optional[str]=..., file_permission_key: Optional[str]=..., timeout: Optional[int]=..., **kwargs: Any) -> Dict[str, Any]: ...
    def upload_file(self, data: Any, length: Optional[int]=..., metadata: Optional[Dict[str, str]]=..., content_settings: Optional[ContentSettings]=..., validate_content: bool=..., max_connections: Optional[int]=..., file_attributes: Union[str, NTFSAttributes]=..., file_creation_time: Union[str, datetime]=..., file_last_write_time: Union[str, datetime]=..., file_permission: Optional[str]=..., file_permission_key: Optional[str]=..., encoding: str=..., timeout: Optional[int]=..., **kwargs: Any) -> Dict[str, Any]: ...
    def start_copy_from_url(self, source_url: str, metadata: Optional[Dict[str, str]]=..., timeout: Optional[int]=..., **kwargs: Any) -> Any: ...
    def abort_copy(self, copy_id: Union[str, FileProperties], timeout: Optional[int]=..., **kwargs: Any) -> Dict[str, Any]: ...
    def download_file(self, offset: Optional[int]=..., length: Optional[int]=..., validate_content: bool=..., timeout: Optional[int]=..., **kwargs: Any) -> Iterable[bytes]: ...
    def delete_file(self, timeout: Optional[int]=..., **kwargs: Optional[Any]) -> None: ...
    def get_file_properties(self, timeout: Optional[int]=..., **kwargs: Any) -> FileProperties: ...
    def set_http_headers(self, content_settings: ContentSettings, file_attributes: Union[str, NTFSAttributes]=..., file_creation_time: Union[str, datetime]=..., file_last_write_time: Union[str, datetime]=..., file_permission: Optional[str]=..., file_permission_key: Optional[str]=..., timeout: Optional[int]=..., **kwargs: Any) -> Dict[str, Any]: ...
    def set_file_metadata(self, metadata: Optional[Dict[str, Any]]=..., timeout: Optional[int]=..., **kwargs: Optional[Any]) -> Dict[str, Any]: ...
    def upload_range(self, data: bytes, start_range: int, end_range: int, validate_content: Optional[bool]=..., timeout: Optional[int]=..., encoding: Any=..., **kwargs: Any) -> Dict[str, Any]: ...
    def upload_range_from_url(self, source_url: str, range_start: int, range_end: int, source_range_start: int, **kwargs: Any) -> Dict[str, Any]: ...
    def get_ranges(self, start_range: Optional[int]=..., end_range: Optional[int]=..., timeout: Optional[int]=..., **kwargs: Any) -> List[dict[str, int]]: ...
    def clear_range(self, start_range: int, end_range: int, timeout: Optional[int]=..., **kwargs: Any) -> Dict[str, Any]: ...
    def resize_file(self, size: int, timeout: Optional[int]=..., **kwargs: Optional[Any]) -> Dict[str, Any]: ...
    def list_handles(self, timeout: int=..., **kwargs: Any) -> ItemPaged[Handle]: ...
    def close_handles(self, handle: Union[str, HandleItem]=..., timeout: Optional[int]=..., **kwargs: Any) -> Any: ...
