# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from azure.identity.aio import ManagedIdentityCredential
from azure.keyvault.secrets.aio import SecretClient
import pytest


@pytest.mark.asyncio
async def test_managed_identity_live(live_managed_identity_config):
    credential = ManagedIdentityCredential(client_id=live_managed_identity_config["client_id"])

    # do something with Key Vault to verify the credential can get a valid token
    client = SecretClient(live_managed_identity_config["vault_url"], credential, logging_enable=True)
    secret = await client.set_secret("managed-identity-test-secret", "value")
    await client.delete_secret(secret.name)
