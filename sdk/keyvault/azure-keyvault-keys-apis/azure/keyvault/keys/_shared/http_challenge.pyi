# Stubs for azure.keyvault.keys._shared.http_challenge (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any, Optional

class HttpChallenge:
    source_authority: Any = ...
    source_uri: Any = ...
    scheme: Any = ...
    server_signature_key: Any = ...
    server_encryption_key: Any = ...
    def __init__(self, request_uri: Any, challenge: Any, response_headers: Optional[Any] = ...) -> None: ...
    def is_bearer_challenge(self): ...
    def is_pop_challenge(self): ...
    def get_value(self, key: Any): ...
    def get_authorization_server(self): ...
    def get_resource(self): ...
    def get_scope(self): ...
    def supports_pop(self): ...
    def supports_message_protection(self): ...
