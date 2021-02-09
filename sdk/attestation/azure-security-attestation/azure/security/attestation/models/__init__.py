# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AttestOpenEnclaveRequest
    from ._models_py3 import AttestSgxEnclaveRequest
    from ._models_py3 import AttestationCertificateManagementBody
    from ._models_py3 import AttestationResponse
    from ._models_py3 import AttestationResult
    from ._models_py3 import CloudError
    from ._models_py3 import CloudErrorBody
    from ._models_py3 import InitTimeData
    from ._models_py3 import JSONWebKey
    from ._models_py3 import JSONWebKeySet
    from ._models_py3 import PolicyCertificatesModificationResult
    from ._models_py3 import PolicyCertificatesModifyResponse
    from ._models_py3 import PolicyCertificatesResponse
    from ._models_py3 import PolicyCertificatesResult
    from ._models_py3 import PolicyResponse
    from ._models_py3 import PolicyResult
    from ._models_py3 import RuntimeData
    from ._models_py3 import StoredAttestationPolicy
    from ._models_py3 import TpmAttestationRequest
    from ._models_py3 import TpmAttestationResponse
except (SyntaxError, ImportError):
    from ._models import AttestOpenEnclaveRequest  # type: ignore
    from ._models import AttestSgxEnclaveRequest  # type: ignore
    from ._models import AttestationCertificateManagementBody  # type: ignore
    from ._models import AttestationResponse  # type: ignore
    from ._models import AttestationResult  # type: ignore
    from ._models import CloudError  # type: ignore
    from ._models import CloudErrorBody  # type: ignore
    from ._models import InitTimeData  # type: ignore
    from ._models import JSONWebKey  # type: ignore
    from ._models import JSONWebKeySet  # type: ignore
    from ._models import PolicyCertificatesModificationResult  # type: ignore
    from ._models import PolicyCertificatesModifyResponse  # type: ignore
    from ._models import PolicyCertificatesResponse  # type: ignore
    from ._models import PolicyCertificatesResult  # type: ignore
    from ._models import PolicyResponse  # type: ignore
    from ._models import PolicyResult  # type: ignore
    from ._models import RuntimeData  # type: ignore
    from ._models import StoredAttestationPolicy  # type: ignore
    from ._models import TpmAttestationRequest  # type: ignore
    from ._models import TpmAttestationResponse  # type: ignore

from ._attestation_client_enums import (
    AttestationType,
    CertificateModification,
    DataType,
    PolicyModification,
)

__all__ = [
    'AttestOpenEnclaveRequest',
    'AttestSgxEnclaveRequest',
    'AttestationCertificateManagementBody',
    'AttestationResponse',
    'AttestationResult',
    'CloudError',
    'CloudErrorBody',
    'InitTimeData',
    'JSONWebKey',
    'JSONWebKeySet',
    'PolicyCertificatesModificationResult',
    'PolicyCertificatesModifyResponse',
    'PolicyCertificatesResponse',
    'PolicyCertificatesResult',
    'PolicyResponse',
    'PolicyResult',
    'RuntimeData',
    'StoredAttestationPolicy',
    'TpmAttestationRequest',
    'TpmAttestationResponse',
    'AttestationType',
    'CertificateModification',
    'DataType',
    'PolicyModification',
]
