# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from msal.oauth2cli import JwtSigner

from .constants import OAUTH_ENDPOINT

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    # pylint:disable=unused-import
    from typing import Any, Mapping


class ClientSecretCredentialBase(object):
    def __init__(self, client_id, secret, tenant_id, **kwargs):
        # type: (str, str, str, Mapping[str, Any]) -> None
        if not client_id:
            raise ValueError("client_id should be the id of an Azure Active Directory application")
        if not secret:
            raise ValueError("secret should be an Azure Active Directory application's client secret")
        if not tenant_id:
            raise ValueError("tenant_id should be an Azure Active Directory tenant's id (also called its 'directory' id)")
        self._form_data = {"client_id": client_id, "client_secret": secret, "grant_type": "client_credentials"}
        super(ClientSecretCredentialBase, self).__init__()


class CertificateCredentialBase(object):
    def __init__(self, client_id, tenant_id, private_key, thumbprint, **kwargs):
        # type: (str, str, str, str, Mapping[str, Any]) -> None
        if not private_key:
            raise ValueError("private_key should be a PEM-encoded private key")
        if not thumbprint:
            raise ValueError("certificate credentials require thumbprint")

        super(CertificateCredentialBase, self).__init__()
        auth_url = OAUTH_ENDPOINT.format(tenant_id)
        signer = JwtSigner(private_key, "RS256", thumbprint)
        client_assertion = signer.sign_assertion(audience=auth_url, issuer=client_id)
        self._form_data = {
            "client_assertion": client_assertion,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_id": client_id,
            "grant_type": "client_credentials",
        }
