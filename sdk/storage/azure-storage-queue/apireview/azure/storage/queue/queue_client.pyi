# Stubs for azure.storage.queue.queue_client (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ._deserialize import deserialize_queue_creation, deserialize_queue_properties
from ._generated import AzureQueueStorage
from ._generated.models import SignedIdentifier, StorageErrorException
from ._message_encoding import TextXMLDecodePolicy, TextXMLEncodePolicy
from ._shared.base_client import StorageAccountHostsMixin, parse_connection_str, parse_query
from ._shared.request_handlers import add_metadata_headers, serialize_iso
from ._shared.response_handlers import process_storage_error, return_headers_and_deserialized, return_response_headers
from ._shared_access_signature import QueueSharedAccessSignature
from .models import AccessPolicy, MessagesPaged, QueueMessage, QueuePermissions, QueueProperties
from azure.core.paging import ItemPaged
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

class QueueClient(StorageAccountHostsMixin):
    queue_name: Any = ...
    def __init__(self, queue_url: str, queue: Optional[Union[QueueProperties, str]]=..., credential: Optional[Any]=..., **kwargs: Any) -> None: ...
    @classmethod
    def from_connection_string(cls: Any, conn_str: str, queue: Union[str, QueueProperties], credential: Any=..., **kwargs: Any) -> None: ...
    def generate_shared_access_signature(self, permission: Optional[Union[QueuePermissions, str]]=..., expiry: Optional[Union[datetime, str]]=..., start: Optional[Union[datetime, str]]=..., policy_id: Optional[str]=..., ip: Optional[str]=..., protocol: Optional[str]=...) -> str: ...
    def create_queue(self, metadata: Optional[Dict[str, Any]]=..., timeout: Optional[int]=..., **kwargs: Optional[Any]) -> None: ...
    def delete_queue(self, timeout: Optional[int]=..., **kwargs: Optional[Any]) -> None: ...
    def get_queue_properties(self, timeout: Optional[int]=..., **kwargs: Optional[Any]) -> QueueProperties: ...
    def set_queue_metadata(self, metadata: Optional[Dict[str, Any]]=..., timeout: Optional[int]=..., **kwargs: Optional[Any]) -> None: ...
    def get_queue_access_policy(self, timeout: Optional[int]=..., **kwargs: Optional[Any]) -> Dict[str, Any]: ...
    def set_queue_access_policy(self, signed_identifiers: Optional[Dict[str, Optional[AccessPolicy]]]=..., timeout: Optional[int]=..., **kwargs: Optional[Any]) -> None: ...
    def enqueue_message(self, content: Any, visibility_timeout: Optional[int]=..., time_to_live: Optional[int]=..., timeout: Optional[int]=..., **kwargs: Optional[Any]) -> QueueMessage: ...
    def receive_messages(self, messages_per_page: Optional[int]=..., visibility_timeout: Optional[int]=..., timeout: Optional[int]=..., **kwargs: Optional[Any]) -> ItemPaged[Message]: ...
    def update_message(self, message: Any, visibility_timeout: int=..., pop_receipt: Optional[str]=..., content: Optional[Any]=..., timeout: Optional[int]=..., **kwargs: Any) -> QueueMessage: ...
    def peek_messages(self, max_messages: Optional[int]=..., timeout: Optional[int]=..., **kwargs: Optional[Any]) -> List[QueueMessage]: ...
    def clear_messages(self, timeout: Optional[int]=..., **kwargs: Optional[Any]) -> None: ...
    def delete_message(self, message: Any, pop_receipt: Optional[str]=..., timeout: Optional[str]=..., **kwargs: Optional[int]) -> None: ...
