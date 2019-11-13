# Stubs for azure.keyvault.certificates._shared._polling (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from azure.core.polling import LROPoller, PollingMethod
from typing import Any, Optional

logger: Any

class KeyVaultOperationPoller(LROPoller):
    def __init__(self, polling_method: PollingMethod) -> None: ...
    def result(self) -> Any: ...
    def wait(self, timeout: Optional[int]=...) -> None: ...

class RecoverDeletedPollingMethod(PollingMethod):
    def __init__(self, command: Any, final_resource: Any, initial_status: Any, finished_status: Any, interval: int = ...) -> None: ...
    def initialize(self, client: Any, initial_response: Any, deserialization_callback: Any) -> None: ...
    def run(self) -> None: ...
    def finished(self) -> bool: ...
    def resource(self) -> Any: ...
    def status(self) -> str: ...

class DeletePollingMethod(RecoverDeletedPollingMethod):
    def __init__(self, command: Any, final_resource: Any, initial_status: Any, finished_status: Any, sd_disabled: Any, interval: int = ...) -> None: ...
    def finished(self) -> bool: ...
