# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------

from ._client import AttestationClient
from ._administration_client import AttestationAdministrationClient
from ._models import (
    AttestationSigner,
    AttestationToken, 
    AttestationData, 
    AttestationPolicyResult, 
    AttestationResult, 
    AttestationTokenValidationException,
    PolicyCertificatesModificationResult,
    AttestationType,
    PolicyModification,
    PolicyCertificatesResult,
    StoredAttestationPolicy,
    CertificateModification)
from ._configuration import TokenValidationOptions
from ._version import VERSION

__version__ = VERSION
__all__ = [
    'AttestationClient',
    'AttestationAdministrationClient',
    'AttestationType',
    'AttestationToken',
    'AttestationSigner',
    'AttestationPolicyResult',
    'PolicyCertificatesResult',
    'AttestationResult',
    'AttestationData',
    'TokenValidationOptions',
    'StoredAttestationPolicy',
    'CertificateModification',
    'PolicyModification',
    'PolicyCertificatesModificationResult',
    'AttestationTokenValidationException',
]

try:
    from ._patch import patch_sdk  # type: ignore
    patch_sdk()
except ImportError:
    pass
