# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------

from ._client_async import AttestationClient
#from .._administration_client import AttestationAdministrationClient
from .._generated.models import AttestationType
from .._version import VERSION

__version__ = VERSION
__all__ = [
    'AttestationClient', 
#'AttestationAdministrationClient', 
    'AttestationType']

try:
    from ._patch import patch_sdk  # type: ignore
    patch_sdk()
except ImportError:
    pass
