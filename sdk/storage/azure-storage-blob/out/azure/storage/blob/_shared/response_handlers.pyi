# Stubs for azure.storage.blob._shared.response_handlers (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from .models import StorageErrorCode, UserDelegationKey, get_enum_value
from .parser import _to_utc_datetime
from azure.core.exceptions import HttpResponseError
from typing import Any

class PartialBatchErrorException(HttpResponseError):
    parts: Any = ...
    def __init__(self, message: Any, response: Any, parts: Any) -> None: ...

def parse_length_from_content_range(content_range: Any): ...
def normalize_headers(headers: Any): ...
def deserialize_metadata(response: Any, obj: Any, headers: Any): ...
def return_response_headers(response: Any, deserialized: Any, response_headers: Any): ...
def return_headers_and_deserialized(response: Any, deserialized: Any, response_headers: Any): ...
def return_context_and_deserialized(response: Any, deserialized: Any, response_headers: Any): ...
def process_storage_error(storage_error: Any) -> None: ...
def parse_to_internal_user_delegation_key(service_user_delegation_key: Any): ...
