# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
# pylint: disable=too-few-public-methods, too-many-instance-attributes
from typing import List, TYPE_CHECKING

from .._api_versions import validate_api_version
from .._headers_mixin import HeadersMixin

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from typing import Any
    from azure.core.credentials import AzureKeyCredential

class SearchIndexingBufferedSenderBase(HeadersMixin):
    """Base of search indexing buffered sender"""
    _ODATA_ACCEPT = "application/json;odata.metadata=none"  # type: str
    _DEFAULT_AUTO_FLUSH_INTERVAL = 60
    _DEFAULT_BATCH_SIZE = 500
    _DEFAULT_MAX_RETRY_COUNT = 3

    def __init__(self, endpoint, index_name, credential, **kwargs):
        # type: (str, str, AzureKeyCredential, **Any) -> None

        api_version = kwargs.pop('api_version', None)
        validate_api_version(api_version)
        self._auto_flush = kwargs.pop('auto_flush', True)
        self._batch_size = kwargs.pop('batch_size', self._DEFAULT_BATCH_SIZE)
        self._auto_flush_interval = kwargs.pop('auto_flush_interval', self._DEFAULT_AUTO_FLUSH_INTERVAL)
        if self._auto_flush_interval <= 0:
            self._auto_flush_interval = 86400
        self._max_retry_count = kwargs.pop('max_retry_count', self._DEFAULT_MAX_RETRY_COUNT)
        self._endpoint = endpoint  # type: str
        self._index_name = index_name  # type: str
        self._index_key = None
        self._credential = credential  # type: AzureKeyCredential
        self._on_new = kwargs.pop('on_new', None)
        self._on_progress = kwargs.pop('on_progress', None)
        self._on_error = kwargs.pop('on_error', None)
        self._on_remove = kwargs.pop('on_remove', None)
        self._retry_counter = {}

    @property
    def batch_size(self):
        # type: () -> int
        return self._batch_size
