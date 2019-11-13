# Stubs for azure.keyvault.certificates.aio._polling_async (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ..models import CertificateOperation, KeyVaultCertificate
from azure.core.polling import AsyncPollingMethod
from typing import Any, Callable, Union

logger: Any

class CreateCertificatePollerAsync(AsyncPollingMethod):
    def __init__(self, get_certificate_command: Any, interval: int = ...) -> None: ...
    def initialize(self, client: Any, initial_response: Any, _: Callable) -> None: ...
    async def run(self) -> None: ...
    def finished(self) -> bool: ...
    def resource(self) -> Union[KeyVaultCertificate, CertificateOperation]: ...
    def status(self) -> str: ...
