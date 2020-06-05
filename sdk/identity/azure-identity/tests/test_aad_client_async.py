# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import functools
from unittest.mock import Mock, patch
from urllib.parse import urlparse

from azure.core.exceptions import ClientAuthenticationError
from azure.identity._constants import EnvironmentVariables
from azure.identity.aio._internal.aad_client import AadClient
import pytest

from helpers import build_aad_response, mock_response

pytestmark = pytest.mark.asyncio


async def test_error_reporting():
    error_name = "everything's sideways"
    error_description = "something went wrong"
    error_response = {"error": error_name, "error_description": error_description}

    response = mock_response(status_code=403, json_payload=error_response)

    async def send(*_, **__):
        return response

    transport = Mock(send=Mock(wraps=send))
    client = AadClient("tenant id", "client id", transport=transport)

    fns = [
        functools.partial(client.obtain_token_by_authorization_code, ("scope",), "code", "uri"),
        functools.partial(client.obtain_token_by_refresh_token, ("scope",), "refresh token"),
    ]

    # exceptions raised for AAD errors should contain AAD's error description
    for fn in fns:
        with pytest.raises(ClientAuthenticationError) as ex:
            await fn()
        message = str(ex.value)
        assert error_name in message and error_description in message
        assert transport.send.call_count == 1
        transport.send.reset_mock()


async def test_exceptions_do_not_expose_secrets():
    secret = "secret"
    body = {"error": "bad thing", "access_token": secret, "refresh_token": secret}
    response = mock_response(status_code=403, json_payload=body)

    async def send(*_, **__):
        return response

    transport = Mock(send=Mock(wraps=send))

    client = AadClient("tenant id", "client id", transport=transport)

    fns = [
        functools.partial(client.obtain_token_by_authorization_code, "code", "uri", ("scope",)),
        functools.partial(client.obtain_token_by_refresh_token, "refresh token", ("scope",)),
    ]

    async def assert_secrets_not_exposed():
        for fn in fns:
            with pytest.raises(ClientAuthenticationError) as ex:
                await fn()
            assert secret not in str(ex.value)
            assert secret not in repr(ex.value)
            assert transport.send.call_count == 1
            transport.send.reset_mock()

    # AAD errors shouldn't provoke exceptions exposing secrets
    await assert_secrets_not_exposed()

    # neither should unexpected AAD responses
    del body["error"]
    await assert_secrets_not_exposed()


@pytest.mark.parametrize("secret", (None, "client secret"))
async def test_authorization_code(secret):
    tenant_id = "tenant-id"
    client_id = "client-id"
    auth_code = "code"
    scope = "scope"
    redirect_uri = "https://localhost"
    access_token = "***"

    async def send(request, **_):
        assert request.data["client_id"] == client_id
        assert request.data["code"] == auth_code
        assert request.data["grant_type"] == "authorization_code"
        assert request.data["redirect_uri"] == redirect_uri
        assert request.data["scope"] == scope
        assert request.data.get("client_secret") == secret

        return mock_response(json_payload={"access_token": access_token, "expires_in": 42})

    transport = Mock(send=Mock(wraps=send))

    client = AadClient(tenant_id, client_id, transport=transport)
    token = await client.obtain_token_by_authorization_code(
        scopes=(scope,), code=auth_code, redirect_uri=redirect_uri, client_secret=secret
    )

    assert token.token == access_token
    assert transport.send.call_count == 1


async def test_refresh_token():
    tenant_id = "tenant-id"
    client_id = "client-id"
    scope = "scope"
    refresh_token = "refresh-token"
    access_token = "***"

    async def send(request, **_):
        assert request.data["client_id"] == client_id
        assert request.data["grant_type"] == "refresh_token"
        assert request.data["refresh_token"] == refresh_token
        assert request.data["scope"] == scope

        return mock_response(json_payload={"access_token": access_token, "expires_in": 42})

    transport = Mock(send=Mock(wraps=send))

    client = AadClient(tenant_id, client_id, transport=transport)
    token = await client.obtain_token_by_refresh_token(scopes=(scope,), refresh_token=refresh_token)

    assert token.token == access_token
    assert transport.send.call_count == 1


@pytest.mark.parametrize("authority", ("localhost", "https://localhost"))
async def test_request_url(authority):
    tenant_id = "expected_tenant"
    parsed_authority = urlparse(authority)
    expected_netloc = parsed_authority.netloc or authority  # "localhost" parses to netloc "", path "localhost"

    async def send(request, **_):
        actual = urlparse(request.url)
        assert actual.scheme == "https"
        assert actual.netloc == expected_netloc
        assert actual.path.startswith("/" + tenant_id)
        return mock_response(json_payload={"token_type": "Bearer", "expires_in": 42, "access_token": "***"})

    client = AadClient(tenant_id, "client id", transport=Mock(send=send), authority=authority)

    await client.obtain_token_by_authorization_code("scope", "code", "uri")
    await client.obtain_token_by_refresh_token("scope", "refresh token")

    # authority can be configured via environment variable
    with patch.dict("os.environ", {EnvironmentVariables.AZURE_AUTHORITY_HOST: authority}, clear=True):
        client = AadClient(tenant_id=tenant_id, client_id="client id", transport=Mock(send=send))
    await client.obtain_token_by_authorization_code("scope", "code", "uri")
    await client.obtain_token_by_refresh_token("scope", "refresh token")
