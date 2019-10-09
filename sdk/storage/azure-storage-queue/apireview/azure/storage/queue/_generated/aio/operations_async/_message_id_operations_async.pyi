# Stubs for azure.storage.queue._generated.aio.operations_async._message_id_operations_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any, Optional

class MessageIdOperations:
    models: Any = ...
    def __init__(self, client: Any, config: Any, serializer: Any, deserializer: Any) -> None: ...
    async def update(self, pop_receipt: Any, visibilitytimeout: Any, queue_message: Optional[Any] = ..., timeout: Optional[Any] = ..., request_id: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def delete(self, pop_receipt: Any, timeout: Optional[Any] = ..., request_id: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
