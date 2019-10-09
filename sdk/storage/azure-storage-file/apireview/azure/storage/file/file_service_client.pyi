# Stubs for azure.storage.file.file_service_client (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from ._generated import AzureFileStorage
from ._generated.models import StorageErrorException, StorageServiceProperties
from ._generated.version import VERSION
from ._shared.base_client import StorageAccountHostsMixin, parse_connection_str, parse_query
from ._shared.models import AccountPermissions, ResourceTypes, Services
from ._shared.response_handlers import process_storage_error
from ._shared.shared_access_signature import SharedAccessSignature
from .models import CorsRule, Metrics, ShareProperties, SharePropertiesPaged
from .share_client import ShareClient
from azure.core.paging import ItemPaged
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

class FileServiceClient(StorageAccountHostsMixin):
    def __init__(self, account_url: str, credential: Optional[Any]=..., **kwargs: Any) -> None: ...
    @classmethod
    def from_connection_string(cls: Any, conn_str: str, credential: Optional[Any]=..., **kwargs: Any) -> FileServiceClient: ...
    def generate_shared_access_signature(self, resource_types: Union[ResourceTypes, str], permission: Union[AccountPermissions, str], expiry: Optional[Union[datetime, str]], start: Optional[Union[datetime, str]]=..., ip: Optional[str]=..., protocol: Optional[str]=...) -> str: ...
    def get_service_properties(self, timeout: Optional[int]=..., **kwargs: Any) -> Dict[str, Any]: ...
    def set_service_properties(self, hour_metrics: Optional[Metrics]=..., minute_metrics: Optional[Metrics]=..., cors: Optional[List[CorsRule]]=..., timeout: Optional[int]=..., **kwargs: Any) -> None: ...
    def list_shares(self, name_starts_with: Optional[str]=..., include_metadata: Optional[bool]=..., include_snapshots: Optional[bool]=..., timeout: Optional[int]=..., **kwargs: Any) -> ItemPaged[ShareProperties]: ...
    def create_share(self, share_name: str, metadata: Optional[Dict[str, str]]=..., quota: Optional[int]=..., timeout: Optional[int]=..., **kwargs: Any) -> ShareClient: ...
    def delete_share(self, share_name: Union[ShareProperties, str], delete_snapshots: Optional[bool]=..., timeout: Optional[int]=..., **kwargs: Any) -> None: ...
    def get_share_client(self, share: Union[ShareProperties, str], snapshot: Optional[Union[Dict[str, Any], str]]=...) -> ShareClient: ...
