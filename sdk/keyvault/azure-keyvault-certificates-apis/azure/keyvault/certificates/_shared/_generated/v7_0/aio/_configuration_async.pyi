# Stubs for azure.keyvault.certificates._shared._generated.v7_0.aio._configuration_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ..version import VERSION
from azure.core.configuration import Configuration
from typing import Any

class KeyVaultClientConfiguration(Configuration):
    generate_client_request_id: bool = ...
    credentials: Any = ...
    def __init__(self, credentials: Any, **kwargs: Any) -> None: ...
