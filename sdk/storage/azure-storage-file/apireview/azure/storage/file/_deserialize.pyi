# Stubs for azure.storage.file._deserialize (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ._shared.response_handlers import deserialize_metadata
from .models import DirectoryProperties, FileProperties, ShareProperties
from typing import Any

def deserialize_share_properties(response: Any, obj: Any, headers: Any): ...
def deserialize_directory_properties(response: Any, obj: Any, headers: Any): ...
def deserialize_file_properties(response: Any, obj: Any, headers: Any): ...
def deserialize_file_stream(response: Any, obj: Any, headers: Any): ...
def deserialize_permission(response: Any, obj: Any, headers: Any): ...
def deserialize_permission_key(response: Any, obj: Any, headers: Any): ...
