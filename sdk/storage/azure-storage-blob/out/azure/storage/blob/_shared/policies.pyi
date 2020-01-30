# Stubs for azure.storage.blob._shared.policies (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from .._version import VERSION
from .models import LocationMode
from azure.core.pipeline import PipelineRequest, PipelineResponse
from azure.core.pipeline.policies import HTTPPolicy, HeadersPolicy, NetworkTraceLoggingPolicy, SansIOHTTPPolicy
from typing import Any, Optional

def encode_base64(data: Any): ...
def is_exhausted(settings: Any): ...
def retry_hook(settings: Any, **kwargs: Any) -> None: ...
def is_retry(response: Any, mode: Any): ...
def urljoin(base_url: Any, stub_url: Any): ...

class QueueMessagePolicy(SansIOHTTPPolicy):
    def on_request(self, request: Any) -> None: ...

class StorageHeadersPolicy(HeadersPolicy):
    request_id_header_name: str = ...
    def on_request(self, request: Any) -> None: ...

class StorageHosts(SansIOHTTPPolicy):
    hosts: Any = ...
    def __init__(self, hosts: Optional[Any] = ..., **kwargs: Any) -> None: ...
    def on_request(self, request: Any) -> None: ...

class StorageLoggingPolicy(NetworkTraceLoggingPolicy):
    def on_request(self, request: Any) -> None: ...
    def on_response(self, request: PipelineResponse, response: Any) -> None: ...

class StorageUserAgentPolicy(SansIOHTTPPolicy):
    def __init__(self, **kwargs: Any) -> None: ...
    def on_request(self, request: Any) -> None: ...

class StorageRequestHook(SansIOHTTPPolicy):
    def __init__(self, **kwargs: Any) -> None: ...
    def on_request(self, request: Any) -> PipelineResponse: ...

class StorageResponseHook(HTTPPolicy):
    def __init__(self, **kwargs: Any) -> None: ...
    def send(self, request: PipelineRequest) -> PipelineResponse: ...

class StorageContentValidation(SansIOHTTPPolicy):
    header_name: str = ...
    def __init__(self, **kwargs: Any) -> None: ...
    @staticmethod
    def get_content_md5(data: Any): ...
    def on_request(self, request: Any) -> None: ...
    def on_response(self, request: Any, response: Any) -> None: ...

class StorageRetryPolicy(HTTPPolicy):
    total_retries: Any = ...
    connect_retries: Any = ...
    read_retries: Any = ...
    status_retries: Any = ...
    retry_to_secondary: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...
    def configure_retries(self, request: Any): ...
    def get_backoff_time(self, settings: Any): ...
    def sleep(self, settings: Any, transport: Any) -> None: ...
    def increment(self, settings: Any, request: Any, response: Optional[Any] = ..., error: Optional[Any] = ...): ...
    def send(self, request: Any): ...

class ExponentialRetry(StorageRetryPolicy):
    initial_backoff: Any = ...
    increment_base: Any = ...
    random_jitter_range: Any = ...
    def __init__(self, initial_backoff: int = ..., increment_base: int = ..., retry_total: int = ..., retry_to_secondary: bool = ..., random_jitter_range: int = ..., **kwargs: Any) -> None: ...
    def get_backoff_time(self, settings: Any): ...

class LinearRetry(StorageRetryPolicy):
    backoff: Any = ...
    random_jitter_range: Any = ...
    def __init__(self, backoff: int = ..., retry_total: int = ..., retry_to_secondary: bool = ..., random_jitter_range: int = ..., **kwargs: Any) -> None: ...
    def get_backoff_time(self, settings: Any): ...

class StorageVersionCheckPolicy(SansIOHTTPPolicy):
    service_name: Any = ...
    version_check_function: Any = ...
    def __init__(self, service_name: Any, version_check_function: Optional[Any] = ...) -> None: ...
    def on_request(self, request: Any) -> None: ...
