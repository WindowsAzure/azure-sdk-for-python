# Stubs for azure.storage.filedatalake._generated.aio.operations_async._path_operations_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any, Optional

class PathOperations:
    models: Any = ...
    def __init__(self, client: Any, config: Any, serializer: Any, deserializer: Any) -> None: ...
    async def create(self, resource: Optional[Any] = ..., continuation: Optional[Any] = ..., mode: Optional[Any] = ..., rename_source: Optional[Any] = ..., source_lease_id: Optional[Any] = ..., properties: Optional[Any] = ..., permissions: Optional[Any] = ..., umask: Optional[Any] = ..., request_id: Optional[Any] = ..., timeout: Optional[Any] = ..., path_http_headers: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., source_modified_access_conditions: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def update(self, action: Any, body: Any, position: Optional[Any] = ..., retain_uncommitted_data: Optional[Any] = ..., close: Optional[Any] = ..., content_length: Optional[Any] = ..., properties: Optional[Any] = ..., owner: Optional[Any] = ..., group: Optional[Any] = ..., permissions: Optional[Any] = ..., acl: Optional[Any] = ..., request_id: Optional[Any] = ..., timeout: Optional[Any] = ..., path_http_headers: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def lease(self, x_ms_lease_action: Any, x_ms_lease_duration: Optional[Any] = ..., x_ms_lease_break_period: Optional[Any] = ..., proposed_lease_id: Optional[Any] = ..., request_id: Optional[Any] = ..., timeout: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def read(self, range: Optional[Any] = ..., x_ms_range_get_content_md5: Optional[Any] = ..., request_id: Optional[Any] = ..., timeout: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def get_properties(self, action: Optional[Any] = ..., upn: Optional[Any] = ..., request_id: Optional[Any] = ..., timeout: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def delete(self, recursive: Optional[Any] = ..., continuation: Optional[Any] = ..., request_id: Optional[Any] = ..., timeout: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def set_access_control(self, timeout: Optional[Any] = ..., owner: Optional[Any] = ..., group: Optional[Any] = ..., permissions: Optional[Any] = ..., acl: Optional[Any] = ..., request_id: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def flush_data(self, timeout: Optional[Any] = ..., position: Optional[Any] = ..., retain_uncommitted_data: Optional[Any] = ..., close: Optional[Any] = ..., content_length: Optional[Any] = ..., request_id: Optional[Any] = ..., path_http_headers: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., modified_access_conditions: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def append_data(self, body: Any, position: Optional[Any] = ..., timeout: Optional[Any] = ..., content_length: Optional[Any] = ..., request_id: Optional[Any] = ..., path_http_headers: Optional[Any] = ..., lease_access_conditions: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
