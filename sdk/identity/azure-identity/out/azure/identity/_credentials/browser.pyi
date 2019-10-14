# Stubs for azure.identity._credentials.browser (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from .._internal import AuthCodeRedirectServer, PublicClientCredential, wrap_exceptions
from azure.core.credentials import AccessToken
from typing import Any

class InteractiveBrowserCredential(PublicClientCredential):
    def __init__(self, client_id: str, **kwargs: Any) -> None: ...
    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken: ...
