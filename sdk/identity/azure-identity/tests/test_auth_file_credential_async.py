# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import os
import json

from azure.identity.aio import AuthFileCredential
from azure.core.exceptions import ClientAuthenticationError

from helpers import Request, mock_response
from helpers_async import async_validating_transport

import pytest
from unittest.mock import patch, mock_open


@pytest.mark.asyncio
async def test_auth_file_credential_parse():
    client_id = 'mockclientid'
    secret = 'mockclientsecret'
    tenant_id =  'mocktenantid'
    authority = 'https://login.microsoftonline.com'
    access_token = '***'

    transport = async_validating_transport(
        requests=[Request(url_substring=tenant_id, required_data={"client_id": client_id, "client_secret": secret})],
        responses=[
            mock_response(
                json_payload={
                    "token_type": "Bearer",
                    "expires_in": 42,
                    "ext_expires_in": 42,
                    "access_token": access_token
                }
            )
        ]
    )

    mock_data = {
        'clientId': client_id,
        'tenantId': tenant_id,
        'clientSecret': secret,
        'activeDirectoryEndpointUrl': authority
    }
    mock_file = mock_open(read_data=json.dumps(mock_data))
    with patch('azure.identity.aio._credentials.auth_file.open', mock_file, create=True) as m:
        token = await AuthFileCredential('authfile', transport=transport).get_token('scope')

    assert token.token == access_token

@pytest.mark.asyncio
async def test_file_not_found():
    with pytest.raises(ClientAuthenticationError) as e:
        credential = AuthFileCredential('Bad*Path')
        token = await credential.get_token("https://mock.scope/.default/")

    assert 'No file found on the given path' in str(e.value)

@pytest.mark.asyncio
async def test_file_no_json():
    with patch('azure.identity.aio._credentials.auth_file.open', mock_open(read_data='not*a*json'), create=True) as m:
        with pytest.raises(ClientAuthenticationError) as nojson_e:
            credential = AuthFileCredential('{}/authfile_nojson.json'.format(os.path.dirname(__file__)))
            token = await credential.get_token("https://mock.scope/.default")

    assert 'Error parsing SDK Auth File' in str(nojson_e.value)

@pytest.mark.asyncio
async def test_file_bad_value():
    with patch('azure.identity.aio._credentials.auth_file.open', mock_open(read_data='{"foo":"bar"}'), create=True) as m:
        with pytest.raises(ClientAuthenticationError) as badvalue_e:
            credential = AuthFileCredential('{}/authfile_badvalue.json'.format(os.path.dirname(__file__)))
            token = await credential.get_token("https://mock.scope/.default")

    assert 'Error parsing SDK Auth File' in str(badvalue_e.value)
