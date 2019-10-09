# Stubs for azure.storage.queue._shared.base_client_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from .authentication import SharedKeyCredentialPolicy
from .base_client import create_configuration
from .constants import DEFAULT_SOCKET_TIMEOUT, STORAGE_OAUTH_SCOPE
from .policies import QueueMessagePolicy, StorageContentValidation, StorageHosts, StorageRequestHook
from .policies_async import AsyncStorageResponseHook
from typing import Any

class AsyncStorageAccountHostsMixin:
    def __enter__(self) -> None: ...
    def __exit__(self, *args: Any) -> None: ...
    async def __aenter__(self): ...
    async def __aexit__(self, *args: Any) -> None: ...
