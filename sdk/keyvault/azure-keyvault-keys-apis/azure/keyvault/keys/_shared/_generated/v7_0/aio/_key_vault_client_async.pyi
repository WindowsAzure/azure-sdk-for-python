# Stubs for azure.keyvault.keys._shared._generated.v7_0.aio._key_vault_client_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ._configuration_async import KeyVaultClientConfiguration
from .operations_async import KeyVaultClientOperationsMixin
from typing import Any

class KeyVaultClient(KeyVaultClientOperationsMixin):
    api_version: str = ...
    def __init__(self, credentials: Any, **kwargs: Any) -> None: ...
    async def __aenter__(self): ...
    async def __aexit__(self, *exc_details: Any) -> None: ...
