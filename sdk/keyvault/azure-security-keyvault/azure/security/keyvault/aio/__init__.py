# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from .keys import KeyClient
from .secrets import SecretClient
from .vault_client import VaultClient

__all__ = ["VaultClient", "KeyClient", "SecretClient"]
