# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import base64
import json
import time

from azure.core.pipeline.policies import SansIOHTTPPolicy
import six

try:
    from unittest import mock
except ImportError:  # python < 3.3
    import mock  # type: ignore


# build_* lifted from msal tests
def build_id_token(
    iss="issuer", sub="subject", aud="my_client_id", exp=None, iat=None, **claims
):  # AAD issues "preferred_username", ADFS issues "upn"
    return "header.%s.signature" % base64.b64encode(
        json.dumps(
            dict(
                {"iss": iss, "sub": sub, "aud": aud, "exp": exp or (time.time() + 100), "iat": iat or time.time()},
                **claims
            )
        ).encode()
    ).decode("utf-8")


def build_aad_response(  # simulate a response from AAD
    uid=None,
    utid=None,  # If present, they will form client_info
    access_token=None,
    expires_in=3600,
    token_type="some type",
    refresh_token=None,
    foci=None,
    id_token=None,  # or something generated by build_id_token()
    error=None,
):
    response = {}
    if uid and utid:  # Mimic the AAD behavior for "client_info=1" request
        response["client_info"] = base64.b64encode(json.dumps({"uid": uid, "utid": utid}).encode()).decode("utf-8")
    if error:
        response["error"] = error
    if access_token:
        response.update({"access_token": access_token, "expires_in": expires_in, "token_type": token_type})
    if refresh_token:
        response["refresh_token"] = refresh_token
    if id_token:
        response["id_token"] = id_token
    if foci:
        response["foci"] = foci
    return response


class Request:
    def __init__(
        self,
        url=None,
        authority=None,
        url_substring=None,
        method=None,
        required_headers={},
        required_data={},
        required_params={},
    ):
        self.authority = authority
        self.method = method
        self.url = url
        self.url_substring = url_substring
        self.required_headers = required_headers
        self.required_data = required_data
        self.required_params = required_params

    def assert_matches(self, request):
        # TODO: rewrite this to report all mismatches, and use the parsed url
        url = six.moves.urllib_parse.urlparse(request.url)

        if self.url:
            assert request.url.split("?")[0] == self.url
        if self.authority:
            assert url.netloc == self.authority, "Expected authority '{}', actual was '{}".format(
                self.authority, url.netloc
            )
        if self.url_substring:
            assert self.url_substring in request.url
        if self.method:
            assert request.method == self.method
        for param, expected_value in self.required_params.items():
            assert request.query.get(param) == expected_value
        for header, expected_value in self.required_headers.items():
            actual = request.headers.get(header)
            if header.lower() == "user-agent":
                # UserAgentPolicy appends the value of $AZURE_HTTP_USER_AGENT, which is set in pipelines.
                assert expected_value in actual
            else:
                assert actual == expected_value, "expected header '{}: {}', actual value was '{}'".format(
                    header, expected_value, actual
                )
        for field, expected_value in self.required_data.items():
            assert request.body.get(field) == expected_value


def mock_response(status_code=200, headers={}, json_payload=None):
    response = mock.Mock(status_code=status_code, headers=headers)
    if json_payload is not None:
        response.text = lambda: json.dumps(json_payload)
        response.headers["content-type"] = "application/json"
        response.content_type = "application/json"
    return response


def get_discovery_response(endpoint="https://a/b"):
    aad_metadata_endpoint_names = ("authorization_endpoint", "token_endpoint", "tenant_discovery_endpoint")
    return mock_response(json_payload={name: endpoint for name in aad_metadata_endpoint_names})


def validating_transport(requests, responses):
    if len(requests) != len(responses):
        raise ValueError("each request must have one response")

    sessions = zip(requests, responses)
    sessions = (s for s in sessions)  # 2.7's zip returns a list, and nesting a generator doesn't break it for 3.x

    def validate_request(request, **kwargs):
        try:
            expected_request, response = next(sessions)
        except StopIteration:
            assert False, "unexpected request: {}".format(request)
        expected_request.assert_matches(request)
        return response

    return mock.Mock(send=mock.Mock(wraps=validate_request))


def urlsafeb64_decode(s):
    if isinstance(s, six.text_type):
        s = s.encode("ascii")

    padding_needed = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + b"=" * padding_needed)


try:
    import asyncio

    def async_validating_transport(requests, responses):
        sync_transport = validating_transport(requests, responses)
        return mock.Mock(send=asyncio.coroutine(sync_transport.send))


except ImportError:
    pass
