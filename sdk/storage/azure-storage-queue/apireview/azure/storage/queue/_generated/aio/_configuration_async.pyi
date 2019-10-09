# Stubs for azure.storage.queue._generated.aio._configuration_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ..version import VERSION
from azure.core.configuration import Configuration
from typing import Any

class AzureQueueStorageConfiguration(Configuration):
    generate_client_request_id: bool = ...
    accept_language: Any = ...
    url: Any = ...
    version: str = ...
    def __init__(self, url: Any, **kwargs: Any) -> None: ...
