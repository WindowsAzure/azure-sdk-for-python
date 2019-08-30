# The MIT License (MIT)
# Copyright (c) 2014 Microsoft Corporation

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from .container_client import ContainerClient
from .cosmos_client import CosmosClient
from .database_client import DatabaseClient
from .user_client import UserClient
from .scripts_client import ScriptsClient
from .documents import (
    ConsistencyLevel,
    DataType,
    IndexKind,
    IndexingMode,
    PermissionMode,
    ProxyConfiguration,
    SSLConfiguration,
    TriggerOperation,
    TriggerType,
)
from .partition_key import PartitionKey
from .permission import Permission
from .version import VERSION

__all__ = (
    "Container",
    "CosmosClient",
    "Database",
    "PartitionKey",
    "Permission",
    "ScriptsClient",
    "User",
    "ConsistencyLevel",
    "DataType",
    "IndexKind",
    "IndexingMode",
    "PermissionMode",
    "ProxyConfiguration",
    "SSLConfiguration",
    "TriggerOperation",
    "TriggerType",
)
__version__ = VERSION