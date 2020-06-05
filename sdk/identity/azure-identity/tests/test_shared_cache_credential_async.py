# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from unittest.mock import Mock, patch
from urllib.parse import urlparse

from azure.core.exceptions import ClientAuthenticationError
from azure.core.pipeline.policies import SansIOHTTPPolicy
from azure.identity import AuthenticationRecord, CredentialUnavailableError
from azure.identity.aio import SharedTokenCacheCredential
from azure.identity._constants import EnvironmentVariables
from azure.identity._internal.shared_token_cache import (
    KNOWN_ALIASES,
    MULTIPLE_ACCOUNTS,
    MULTIPLE_MATCHING_ACCOUNTS,
    NO_ACCOUNTS,
    NO_MATCHING_ACCOUNTS,
)
from azure.identity._internal.user_agent import USER_AGENT
from msal import TokenCache
import pytest

from helpers import build_aad_response, build_id_token, mock_response, Request
from helpers_async import async_validating_transport, AsyncMockTransport
from test_shared_cache_credential import get_account_event, populated_cache


@pytest.mark.asyncio
async def test_no_scopes():
    """The credential should raise when get_token is called with no scopes"""

    credential = SharedTokenCacheCredential(_cache=TokenCache())
    with pytest.raises(ClientAuthenticationError):
        await credential.get_token()


@pytest.mark.asyncio
async def test_close():
    transport = AsyncMockTransport()
    credential = SharedTokenCacheCredential(
        _cache=populated_cache(get_account_event("test@user", "uid", "utid")), transport=transport
    )

    await credential.close()

    assert transport.__aexit__.call_count == 1


@pytest.mark.asyncio
async def test_context_manager():
    transport = AsyncMockTransport()
    credential = SharedTokenCacheCredential(
        _cache=populated_cache(get_account_event("test@user", "uid", "utid")), transport=transport
    )

    async with credential:
        assert transport.__aenter__.call_count == 1

    assert transport.__aenter__.call_count == 1
    assert transport.__aexit__.call_count == 1


@pytest.mark.asyncio
async def test_context_manager_no_cache():
    """the credential shouldn't open/close sessions when instantiated in an environment with no cache"""

    transport = AsyncMockTransport()
    with patch.dict("azure.identity._internal.shared_token_cache.os.environ", {}, clear=True):
        # clearing the environment ensures the credential won't try to load a cache
        credential = SharedTokenCacheCredential(transport=transport)

    async with credential:
        assert transport.__aenter__.call_count == 0

    assert transport.__aenter__.call_count == 0
    assert transport.__aexit__.call_count == 0


@pytest.mark.asyncio
async def test_policies_configurable():
    policy = Mock(spec_set=SansIOHTTPPolicy, on_request=Mock())

    async def send(*_, **__):
        return mock_response(json_payload=build_aad_response(access_token="**"))

    credential = SharedTokenCacheCredential(
        _cache=populated_cache(get_account_event("test@user", "uid", "utid")),
        policies=[policy],
        transport=Mock(send=send),
    )

    await credential.get_token("scope")

    assert policy.on_request.called


@pytest.mark.asyncio
async def test_user_agent():
    transport = async_validating_transport(
        requests=[Request(required_headers={"User-Agent": USER_AGENT})],
        responses=[mock_response(json_payload=build_aad_response(access_token="**"))],
    )

    credential = SharedTokenCacheCredential(
        _cache=populated_cache(get_account_event("test@user", "uid", "utid")), transport=transport
    )

    await credential.get_token("scope")


@pytest.mark.parametrize("authority", ("localhost", "https://localhost"))
def test_authority(authority):
    """the credential should accept an authority, with or without scheme, as an argument or environment variable"""

    parsed_authority = urlparse(authority)
    expected_netloc = parsed_authority.netloc or authority  # "localhost" parses to netloc "", path "localhost"

    class MockCredential(SharedTokenCacheCredential):
        def _get_auth_client(self, authority=None, **kwargs):
            actual = urlparse(authority)
            assert actual.scheme == "https"
            assert actual.netloc == expected_netloc

    transport = Mock(send=Mock(side_effect=Exception("credential shouldn't send a request")))
    MockCredential(_cache=TokenCache(), authority=authority, transport=transport)

    with patch.dict("os.environ", {EnvironmentVariables.AZURE_AUTHORITY_HOST: authority}, clear=True):
        MockCredential(_cache=TokenCache(), authority=authority, transport=transport)


@pytest.mark.asyncio
async def test_empty_cache():
    """the credential should raise CredentialUnavailableError when the cache is empty"""

    with pytest.raises(CredentialUnavailableError, match=NO_ACCOUNTS):
        await SharedTokenCacheCredential(_cache=TokenCache()).get_token("scope")
    with pytest.raises(CredentialUnavailableError, match=NO_ACCOUNTS):
        await SharedTokenCacheCredential(_cache=TokenCache(), username="not@cache").get_token("scope")
    with pytest.raises(CredentialUnavailableError, match=NO_ACCOUNTS):
        await SharedTokenCacheCredential(_cache=TokenCache(), tenant_id="not-cached").get_token("scope")
    with pytest.raises(CredentialUnavailableError, match=NO_ACCOUNTS):
        credential = SharedTokenCacheCredential(_cache=TokenCache(), tenant_id="not-cached", username="not@cache")
        await credential.get_token("scope")


@pytest.mark.asyncio
async def test_no_matching_account_for_username():
    """one cached account, username specified, username doesn't match -> credential should raise"""

    upn = "spam@eggs"
    tenant = "some-guid"
    account = get_account_event(username=upn, uid="uid", utid=tenant, refresh_token="refresh-token")
    cache = populated_cache(account)

    with pytest.raises(CredentialUnavailableError) as ex:
        await SharedTokenCacheCredential(_cache=cache, username="not" + upn).get_token("scope")

    assert ex.value.message.startswith(NO_MATCHING_ACCOUNTS[: NO_MATCHING_ACCOUNTS.index("{")])
    assert "not" + upn in ex.value.message


@pytest.mark.asyncio
async def test_no_matching_account_for_tenant():
    """one cached account, tenant specified, tenant doesn't match -> credential should raise"""

    upn = "spam@eggs"
    tenant = "some-guid"
    account = get_account_event(username=upn, uid="uid", utid=tenant, refresh_token="refresh-token")
    cache = populated_cache(account)

    with pytest.raises(CredentialUnavailableError) as ex:
        await SharedTokenCacheCredential(_cache=cache, tenant_id="not-" + tenant).get_token("scope")

    assert ex.value.message.startswith(NO_MATCHING_ACCOUNTS[: NO_MATCHING_ACCOUNTS.index("{")])
    assert "not-" + tenant in ex.value.message


@pytest.mark.asyncio
async def test_no_matching_account_for_tenant_and_username():
    """one cached account, tenant and username specified, neither match -> credential should raise"""

    upn = "spam@eggs"
    tenant = "some-guid"
    account = get_account_event(username=upn, uid="uid", utid=tenant, refresh_token="refresh-token")
    cache = populated_cache(account)

    with pytest.raises(CredentialUnavailableError) as ex:
        await SharedTokenCacheCredential(_cache=cache, tenant_id="not-" + tenant, username="not" + upn).get_token(
            "scope"
        )

    assert ex.value.message.startswith(NO_MATCHING_ACCOUNTS[: NO_MATCHING_ACCOUNTS.index("{")])
    assert "not" + upn in ex.value.message and "not-" + tenant in ex.value.message


@pytest.mark.asyncio
async def test_no_matching_account_for_tenant_or_username():
    """two cached accounts, username and tenant specified, one account matches each -> credential should raise"""

    refresh_token_a = "refresh-token-a"
    refresh_token_b = "refresh-token-b"
    upn_a = "a@foo"
    upn_b = "b@foo"
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"
    account_a = get_account_event(username=upn_a, uid="uid_a", utid=tenant_a, refresh_token=refresh_token_a)
    account_b = get_account_event(username=upn_b, uid="uid_b", utid=tenant_b, refresh_token=refresh_token_b)
    cache = populated_cache(account_a, account_b)

    transport = Mock(side_effect=Exception())  # credential shouldn't use the network

    credential = SharedTokenCacheCredential(username=upn_a, tenant_id=tenant_b, _cache=cache, transport=transport)
    with pytest.raises(CredentialUnavailableError) as ex:
        await credential.get_token("scope")
    assert ex.value.message.startswith(NO_MATCHING_ACCOUNTS[: NO_MATCHING_ACCOUNTS.index("{")])
    assert upn_a in ex.value.message and tenant_b in ex.value.message

    credential = SharedTokenCacheCredential(username=upn_b, tenant_id=tenant_a, _cache=cache, transport=transport)
    with pytest.raises(CredentialUnavailableError) as ex:
        await credential.get_token("scope")
    assert ex.value.message.startswith(NO_MATCHING_ACCOUNTS[: NO_MATCHING_ACCOUNTS.index("{")])
    assert upn_b in ex.value.message and tenant_a in ex.value.message


@pytest.mark.asyncio
async def test_single_account_matching_username():
    """one cached account, username specified, username matches -> credential should auth that account"""

    upn = "spam@eggs"
    refresh_token = "refresh-token"
    scope = "scope"
    account = get_account_event(uid="uid_a", utid="utid", username=upn, refresh_token=refresh_token)
    cache = populated_cache(account)

    expected_token = "***"
    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": refresh_token, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_token))],
    )
    credential = SharedTokenCacheCredential(_cache=cache, transport=transport, username=upn)
    token = await credential.get_token(scope)
    assert token.token == expected_token


@pytest.mark.asyncio
async def test_single_account_matching_tenant():
    """one cached account, tenant specified, tenant matches -> credential should auth that account"""

    tenant_id = "tenant-id"
    refresh_token = "refresh-token"
    scope = "scope"
    account = get_account_event(uid="uid_a", utid=tenant_id, username="spam@eggs", refresh_token=refresh_token)
    cache = populated_cache(account)

    expected_token = "***"
    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": refresh_token, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_token))],
    )
    credential = SharedTokenCacheCredential(_cache=cache, transport=transport, tenant_id=tenant_id)
    token = await credential.get_token(scope)
    assert token.token == expected_token


@pytest.mark.asyncio
async def test_single_account_matching_tenant_and_username():
    """one cached account, tenant and username specified, both match -> credential should auth that account"""

    upn = "spam@eggs"
    tenant_id = "tenant-id"
    refresh_token = "refresh-token"
    scope = "scope"
    account = get_account_event(uid="uid_a", utid=tenant_id, username=upn, refresh_token=refresh_token)
    cache = populated_cache(account)

    expected_token = "***"
    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": refresh_token, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_token))],
    )
    credential = SharedTokenCacheCredential(_cache=cache, transport=transport, tenant_id=tenant_id, username=upn)
    token = await credential.get_token(scope)
    assert token.token == expected_token


@pytest.mark.asyncio
async def test_single_account():
    """one cached account, no username specified -> credential should auth that account"""

    refresh_token = "refresh-token"
    scope = "scope"
    account = get_account_event(uid="uid_a", utid="utid", username="spam@eggs", refresh_token=refresh_token)
    cache = populated_cache(account)

    expected_token = "***"
    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": refresh_token, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_token))],
    )
    credential = SharedTokenCacheCredential(_cache=cache, transport=transport)

    token = await credential.get_token(scope)
    assert token.token == expected_token


@pytest.mark.asyncio
async def test_no_refresh_token():
    """one cached account, account has no refresh token -> credential should raise"""

    account = get_account_event(uid="uid_a", utid="utid", username="spam@eggs", refresh_token=None)
    cache = populated_cache(account)

    transport = Mock(side_effect=Exception())  # credential shouldn't use the network

    credential = SharedTokenCacheCredential(_cache=cache, transport=transport)
    with pytest.raises(CredentialUnavailableError, match=NO_ACCOUNTS):
        await credential.get_token("scope")

    credential = SharedTokenCacheCredential(_cache=cache, transport=transport, username="not@cache")
    with pytest.raises(CredentialUnavailableError, match=NO_ACCOUNTS):
        await credential.get_token("scope")


@pytest.mark.asyncio
async def test_two_accounts_no_username_or_tenant():
    """two cached accounts, no username or tenant specified -> credential should raise"""

    upn_a = "a@foo"
    upn_b = "b@foo"
    account_a = get_account_event(username=upn_a, uid="uid_a", utid="utid")
    account_b = get_account_event(username=upn_b, uid="uid_b", utid="utid")
    cache = populated_cache(account_a, account_b)

    # credential can't select an identity => it shouldn't use the network
    transport = Mock(side_effect=Exception())

    # two users in the cache, no username specified -> CredentialUnavailableError
    credential = SharedTokenCacheCredential(_cache=cache, transport=transport)
    with pytest.raises(ClientAuthenticationError, match=MULTIPLE_ACCOUNTS) as ex:
        await credential.get_token("scope")


@pytest.mark.asyncio
async def test_two_accounts_username_specified():
    """two cached accounts, username specified, one account matches -> credential should auth that account"""

    scope = "scope"
    expected_refresh_token = "refresh-token-a"
    upn_a = "a@foo"
    upn_b = "b@foo"
    account_a = get_account_event(username=upn_a, uid="uid_a", utid="utid", refresh_token=expected_refresh_token)
    account_b = get_account_event(username=upn_b, uid="uid_b", utid="utid", refresh_token="refresh_token_b")
    cache = populated_cache(account_a, account_b)

    expected_token = "***"
    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": expected_refresh_token, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_token))],
    )
    credential = SharedTokenCacheCredential(username=upn_a, _cache=cache, transport=transport)
    token = await credential.get_token(scope)
    assert token.token == expected_token


@pytest.mark.asyncio
async def test_two_accounts_tenant_specified():
    """two cached accounts, tenant specified, one account matches -> credential should auth that account"""

    scope = "scope"
    expected_refresh_token = "refresh-token-a"
    upn_a = "a@foo"
    upn_b = "b@foo"
    tenant_id = "tenant-id"
    account_a = get_account_event(username=upn_a, uid="uid_a", utid=tenant_id, refresh_token=expected_refresh_token)
    account_b = get_account_event(username=upn_b, uid="uid_b", utid="utid", refresh_token="refresh_token_b")
    cache = populated_cache(account_a, account_b)

    expected_token = "***"
    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": expected_refresh_token, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_token))],
    )
    credential = SharedTokenCacheCredential(tenant_id=tenant_id, _cache=cache, transport=transport)
    token = await credential.get_token(scope)
    assert token.token == expected_token


@pytest.mark.asyncio
async def test_two_accounts_tenant_and_username_specified():
    """two cached accounts, tenant and username specified, one account matches both -> credential should auth that account"""

    scope = "scope"
    expected_refresh_token = "refresh-token-a"
    upn_a = "a@foo"
    upn_b = "b@foo"
    tenant_id = "tenant-id"
    account_a = get_account_event(username=upn_a, uid="uid_a", utid=tenant_id, refresh_token=expected_refresh_token)
    account_b = get_account_event(username=upn_b, uid="uid_b", utid="utid", refresh_token="refresh_token_b")
    cache = populated_cache(account_a, account_b)

    expected_token = "***"
    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": expected_refresh_token, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_token))],
    )
    credential = SharedTokenCacheCredential(tenant_id=tenant_id, username=upn_a, _cache=cache, transport=transport)
    token = await credential.get_token(scope)
    assert token.token == expected_token


@pytest.mark.asyncio
async def test_same_username_different_tenants():
    """two cached accounts, same username, different tenants"""

    access_token_a = "access-token-a"
    access_token_b = "access-token-b"
    refresh_token_a = "refresh-token-a"
    refresh_token_b = "refresh-token-b"

    upn = "spam@eggs"
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"
    account_a = get_account_event(username=upn, uid="another-guid", utid=tenant_a, refresh_token=refresh_token_a)
    account_b = get_account_event(username=upn, uid="more-guid", utid=tenant_b, refresh_token=refresh_token_b)
    cache = populated_cache(account_a, account_b)

    # with no tenant specified the credential can't select an identity
    transport = Mock(side_effect=Exception())  # (so it shouldn't use the network)
    credential = SharedTokenCacheCredential(username=upn, _cache=cache, transport=transport)
    with pytest.raises(CredentialUnavailableError) as ex:
        await credential.get_token("scope")

    assert ex.value.message.startswith(MULTIPLE_MATCHING_ACCOUNTS[: MULTIPLE_MATCHING_ACCOUNTS.index("{")])
    assert upn in ex.value.message

    # with tenant specified, the credential should auth the matching account
    scope = "scope"
    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": refresh_token_a, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=access_token_a))],
    )
    credential = SharedTokenCacheCredential(tenant_id=tenant_a, _cache=cache, transport=transport)
    token = await credential.get_token(scope)
    assert token.token == access_token_a

    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": refresh_token_b, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=access_token_b))],
    )
    credential = SharedTokenCacheCredential(tenant_id=tenant_b, _cache=cache, transport=transport)
    token = await credential.get_token(scope)
    assert token.token == access_token_b


@pytest.mark.asyncio
async def test_same_tenant_different_usernames():
    """two cached accounts, same tenant, different usernames"""

    access_token_a = "access-token-a"
    access_token_b = "access-token-b"
    refresh_token_a = "refresh-token-a"
    refresh_token_b = "refresh-token-b"

    upn_a = "spam@eggs"
    upn_b = "eggs@spam"
    tenant_id = "the-tenant"
    account_a = get_account_event(username=upn_a, uid="another-guid", utid=tenant_id, refresh_token=refresh_token_a)
    account_b = get_account_event(username=upn_b, uid="more-guid", utid=tenant_id, refresh_token=refresh_token_b)
    cache = populated_cache(account_a, account_b)

    # with no username specified the credential can't select an identity
    transport = Mock(side_effect=Exception())  # (so it shouldn't use the network)
    credential = SharedTokenCacheCredential(tenant_id=tenant_id, _cache=cache, transport=transport)
    with pytest.raises(CredentialUnavailableError) as ex:
        await credential.get_token("scope")

    assert ex.value.message.startswith(MULTIPLE_MATCHING_ACCOUNTS[: MULTIPLE_MATCHING_ACCOUNTS.index("{")])
    assert tenant_id in ex.value.message

    # with a username specified, the credential should auth the matching account
    scope = "scope"
    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": refresh_token_b, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=access_token_a))],
    )
    credential = SharedTokenCacheCredential(username=upn_b, _cache=cache, transport=transport)
    token = await credential.get_token(scope)
    assert token.token == access_token_a

    transport = async_validating_transport(
        requests=[Request(required_data={"refresh_token": refresh_token_a, "scope": scope})],
        responses=[mock_response(json_payload=build_aad_response(access_token=access_token_a))],
    )
    credential = SharedTokenCacheCredential(username=upn_a, _cache=cache, transport=transport)
    token = await credential.get_token(scope)
    assert token.token == access_token_a


@pytest.mark.asyncio
async def test_authority_aliases():
    """the credential should use a refresh token valid for any known alias of its authority"""

    expected_access_token = "access-token"

    for authority in KNOWN_ALIASES:
        # cache a token for this authority
        expected_refresh_token = authority.replace(".", "")
        account = get_account_event(
            "spam@eggs", "uid", "tenant", authority=authority, refresh_token=expected_refresh_token
        )
        cache = populated_cache(account)

        # the token should be acceptable for this authority itself
        transport = async_validating_transport(
            requests=[Request(authority=authority, required_data={"refresh_token": expected_refresh_token})],
            responses=[mock_response(json_payload=build_aad_response(access_token=expected_access_token))],
        )
        credential = SharedTokenCacheCredential(authority=authority, _cache=cache, transport=transport)
        token = await credential.get_token("scope")
        assert token.token == expected_access_token

        # it should also be acceptable for every known alias of this authority
        for alias in KNOWN_ALIASES[authority]:
            transport = async_validating_transport(
                requests=[Request(authority=alias, required_data={"refresh_token": expected_refresh_token})],
                responses=[mock_response(json_payload=build_aad_response(access_token=expected_access_token))],
            )
            credential = SharedTokenCacheCredential(authority=alias, _cache=cache, transport=transport)
            token = await credential.get_token("scope")
            assert token.token == expected_access_token


@pytest.mark.asyncio
async def test_authority_with_no_known_alias():
    """given an appropriate token, an authority with no known aliases should work"""

    authority = "unknown.authority"
    expected_access_token = "access-token"
    expected_refresh_token = "refresh-token"
    account = get_account_event("spam@eggs", "uid", "tenant", authority=authority, refresh_token=expected_refresh_token)
    cache = populated_cache(account)
    transport = async_validating_transport(
        requests=[Request(authority=authority, required_data={"refresh_token": expected_refresh_token})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_access_token))],
    )
    credential = SharedTokenCacheCredential(authority=authority, _cache=cache, transport=transport)
    token = await credential.get_token("scope")
    assert token.token == expected_access_token


@pytest.mark.asyncio
async def test_authority_environment_variable():
    """the credential should accept an authority by environment variable when none is otherwise specified"""

    authority = "localhost"
    expected_access_token = "access-token"
    expected_refresh_token = "refresh-token"
    account = get_account_event("spam@eggs", "uid", "tenant", authority=authority, refresh_token=expected_refresh_token)
    cache = populated_cache(account)
    transport = async_validating_transport(
        requests=[Request(authority=authority, required_data={"refresh_token": expected_refresh_token})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_access_token))],
    )
    with patch.dict("os.environ", {EnvironmentVariables.AZURE_AUTHORITY_HOST: authority}, clear=True):
        credential = SharedTokenCacheCredential(transport=transport, _cache=cache)
    token = await credential.get_token("scope")
    assert token.token == expected_access_token


@pytest.mark.asyncio
async def test_authentication_record_empty_cache():
    record = AuthenticationRecord("tenant_id", "client_id", "authority", "home_account_id", "username")
    transport = Mock(side_effect=Exception("the credential shouldn't send a request"))
    credential = SharedTokenCacheCredential(authentication_record=record, transport=transport, _cache=TokenCache())

    with pytest.raises(CredentialUnavailableError):
        await credential.get_token("scope")


@pytest.mark.asyncio
async def test_authentication_record_no_match():
    tenant_id = "tenant-id"
    client_id = "client-id"
    authority = "localhost"
    object_id = "object-id"
    home_account_id = object_id + "." + tenant_id
    username = "me"
    record = AuthenticationRecord(tenant_id, client_id, authority, home_account_id, username)

    transport = Mock(side_effect=Exception("the credential shouldn't send a request"))
    cache = populated_cache(
        get_account_event(
            "not-" + username, "not-" + object_id, "different-" + tenant_id, client_id="not-" + client_id,
        ),
    )
    credential = SharedTokenCacheCredential(authentication_record=record, transport=transport, _cache=cache)

    with pytest.raises(CredentialUnavailableError):
        await credential.get_token("scope")


@pytest.mark.asyncio
async def test_authentication_record():
    tenant_id = "tenant-id"
    client_id = "client-id"
    authority = "localhost"
    object_id = "object-id"
    home_account_id = object_id + "." + tenant_id
    username = "me"
    record = AuthenticationRecord(tenant_id, client_id, authority, home_account_id, username)

    expected_access_token = "****"
    expected_refresh_token = "**"
    account = get_account_event(
        username, object_id, tenant_id, authority=authority, client_id=client_id, refresh_token=expected_refresh_token
    )
    cache = populated_cache(account)

    transport = async_validating_transport(
        requests=[Request(authority=authority, required_data={"refresh_token": expected_refresh_token})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_access_token))],
    )
    credential = SharedTokenCacheCredential(authentication_record=record, transport=transport, _cache=cache)

    token = await credential.get_token("scope")
    assert token.token == expected_access_token


@pytest.mark.asyncio
async def test_auth_record_multiple_accounts_for_username():
    tenant_id = "tenant-id"
    client_id = "client-id"
    authority = "localhost"
    object_id = "object-id"
    home_account_id = object_id + "." + tenant_id
    username = "me"
    record = AuthenticationRecord(tenant_id, client_id, authority, home_account_id, username)

    expected_access_token = "****"
    expected_refresh_token = "**"
    expected_account = get_account_event(
        username, object_id, tenant_id, authority=authority, client_id=client_id, refresh_token=expected_refresh_token
    )
    cache = populated_cache(
        expected_account,
        get_account_event(  # this account matches all but the record's tenant
            username,
            object_id,
            "different-" + tenant_id,
            authority=authority,
            client_id=client_id,
            refresh_token="not-" + expected_refresh_token,
        ),
    )

    transport = async_validating_transport(
        requests=[Request(authority=authority, required_data={"refresh_token": expected_refresh_token})],
        responses=[mock_response(json_payload=build_aad_response(access_token=expected_access_token))],
    )
    credential = SharedTokenCacheCredential(authentication_record=record, transport=transport, _cache=cache)

    token = await credential.get_token("scope")
    assert token.token == expected_access_token


def test_authentication_record_authenticating_tenant():
    """when given a record and 'tenant_id', the credential should authenticate in the latter"""

    expected_tenant_id = "tenant-id"
    record = AuthenticationRecord("not- " + expected_tenant_id, "...", "...", "...", "...")

    with patch.object(SharedTokenCacheCredential, "_get_auth_client") as get_auth_client:
        SharedTokenCacheCredential(authentication_record=record, _cache=TokenCache(), tenant_id=expected_tenant_id)

    assert get_auth_client.call_count == 1
    _, kwargs = get_auth_client.call_args
    assert kwargs["tenant_id"] == expected_tenant_id
