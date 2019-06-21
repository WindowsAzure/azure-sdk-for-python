# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from .credentials import (
    CertificateCredential,
    ClientSecretCredential,
    EnvironmentCredential,
    ManagedIdentityCredential,
    ChainedTokenCredential,
)


class DefaultAzureCredential(ChainedTokenCredential):
    """default credential is environment followed by MSI/IMDS"""

    def __init__(self, **kwargs):
        super(DefaultAzureCredential, self).__init__(
            EnvironmentCredential(**kwargs), ManagedIdentityCredential(**kwargs)
        )


__all__ = [
    "CertificateCredential",
    "ClientSecretCredential",
    "DefaultAzureCredential",
    "EnvironmentCredential",
    "ManagedIdentityCredential",
    "ChainedTokenCredential",
]

try:
    from .aio import (
        AsyncCertificateCredential,
        AsyncClientSecretCredential,
        AsyncDefaultAzureCredential,
        AsyncEnvironmentCredential,
        AsyncManagedIdentityCredential,
        AsyncChainedTokenCredential,
    )

    __all__.extend(
        [
            "AsyncCertificateCredential",
            "AsyncClientSecretCredential",
            "AsyncDefaultAzureCredential",
            "AsyncEnvironmentCredential",
            "AsyncManagedIdentityCredential",
            "AsyncChainedTokenCredential",
        ]
    )
except (ImportError, SyntaxError):
    pass
