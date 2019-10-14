# Stubs for azure.keyvault.certificates._shared.async_client_base (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from .._user_agent import USER_AGENT
from ._generated import KeyVaultClient
from azure.core.credentials import TokenCredential
from azure.core.pipeline.transport import AsyncHttpTransport

class AsyncKeyVaultClientBase:
    def __init__(self, vault_endpoint: str, credential: TokenCredential, transport: AsyncHttpTransport=..., api_version: str=..., **kwargs: '**Any') -> None: ...
    @property
    def vault_endpoint(self) -> str: ...
