# Stubs for azure.storage.queue._shared.request_handlers (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any, Dict, Optional

def serialize_iso(attr: Any): ...
def get_length(data: Any): ...
def read_length(data: Any): ...
def validate_and_format_range_headers(start_range: Any, end_range: Any, start_range_required: bool = ..., end_range_required: bool = ..., check_content_md5: bool = ..., align_to_page: bool = ...): ...
def add_metadata_headers(metadata: Optional[Dict[str, str]]=...) -> Dict[str, str]: ...
