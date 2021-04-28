# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------

from ._log_query_client import LogQueryClient
from ._generated.models import QueryResults
from ._version import VERSION

__all__ = [
    "LogQueryClient",
    "QueryResults"
]

__version__ = VERSION
