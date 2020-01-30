# Stubs for azure.storage.blob._generated.operations._directory_operations (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any, Optional

class DirectoryOperations:
    models: Any = ...
    resource: str = ...
    def __init__(self, client: Any, config: Any, serializer: Any, deserializer: Any) -> None: ...
    def create(self, timeout: Optional[Any] = ..., directory_properties: Optional[Any] = ..., posix_permissions: Optional[Any] = ..., posix_umask: Optional[Any] = ..., request_id: Optional[Any] = ..., directory_http_headers: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def rename(self, rename_source: Any, timeout: Optional[Any] = ..., marker: Optional[Any] = ..., path_rename_mode: Optional[Any] = ..., directory_properties: Optional[Any] = ..., posix_permissions: Optional[Any] = ..., posix_umask: Optional[Any] = ..., source_lease_id: Optional[Any] = ..., request_id: Optional[Any] = ..., directory_http_headers: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., source_modified_access_conditions: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def delete(self, recursive_directory_delete: Any, timeout: Optional[Any] = ..., marker: Optional[Any] = ..., request_id: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def set_access_control(self, timeout: Optional[Any] = ..., owner: Optional[Any] = ..., group: Optional[Any] = ..., posix_permissions: Optional[Any] = ..., posix_acl: Optional[Any] = ..., request_id: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_access_control(self, timeout: Optional[Any] = ..., upn: Optional[Any] = ..., request_id: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
