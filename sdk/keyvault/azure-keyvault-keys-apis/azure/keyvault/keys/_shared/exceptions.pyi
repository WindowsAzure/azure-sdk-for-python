# Stubs for azure.keyvault.keys._shared.exceptions (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from azure.core.exceptions import AzureError
from azure.core.pipeline.transport import HttpResponse
from typing import Any, Type

def get_exception_for_key_vault_error(cls: Type[AzureError], response: HttpResponse) -> AzureError: ...

error_map: Any
