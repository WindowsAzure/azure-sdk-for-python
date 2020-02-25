from ._generated.models import IndexAction as IndexAction
from typing import Any, List

def flatten_args(args: Any): ...

class IndexBatch:
    def __init__(self) -> None: ...
    def add_upload_documents(self, *documents: Any) -> None: ...
    def add_delete_documents(self, *documents: Any) -> None: ...
    def add_merge_documents(self, *documents: Any) -> None: ...
    def add_merge_or_upload_documents(self, *documents: Any) -> None: ...
    @property
    def actions(self) -> List[IndexAction]: ...
