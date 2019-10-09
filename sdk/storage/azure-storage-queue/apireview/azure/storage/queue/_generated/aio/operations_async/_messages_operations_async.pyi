# Stubs for azure.storage.queue._generated.aio.operations_async._messages_operations_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any, Optional

class MessagesOperations:
    models: Any = ...
    peekonly: str = ...
    def __init__(self, client: Any, config: Any, serializer: Any, deserializer: Any) -> None: ...
    async def dequeue(self, number_of_messages: Optional[Any] = ..., visibilitytimeout: Optional[Any] = ..., timeout: Optional[Any] = ..., request_id: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def clear(self, timeout: Optional[Any] = ..., request_id: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def enqueue(self, queue_message: Optional[Any] = ..., visibilitytimeout: Optional[Any] = ..., message_time_to_live: Optional[Any] = ..., timeout: Optional[Any] = ..., request_id: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
    async def peek(self, number_of_messages: Optional[Any] = ..., timeout: Optional[Any] = ..., request_id: Optional[Any] = ..., *, cls: Optional[Any] = ..., **kwargs: Any): ...
