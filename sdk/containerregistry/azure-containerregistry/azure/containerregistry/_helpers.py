# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import re

from azure.core.exceptions import ServiceRequestError

BEARER = "Bearer"
AUTHENTICATION_CHALLENGE_PARAMS_PATTERN = re.compile('(?:(\\w+)="([^""]*)")+')


def _is_tag(tag_or_digest):
    # type: (str) -> bool
    tag = tag_or_digest.split(":")
    return not (len(tag) == 2 and tag[0].startswith(u"sha"))


def _clean(matches):
    # type: (List[str]) -> None
    """This method removes empty strings and commas from the regex matching of the Challenge header"""
    while True:
        try:
            matches.remove("")
        except ValueError:
            break

    while True:
        try:
            matches.remove(",")
        except ValueError:
            return


def _parse_challenge(header):
    # type: (str) -> Dict[str, str]
    """Parse challenge header into service and scope"""
    ret = {}
    if header.startswith(BEARER):
        challenge_params = header[len(BEARER) + 1 :]

        matches = re.split(AUTHENTICATION_CHALLENGE_PARAMS_PATTERN, challenge_params)
        _clean(matches)
        ret = {}
        for i in range(0, len(matches), 2):
            ret[matches[i]] = matches[i + 1]

    return ret


def _enforce_https(request):
    # type: (PipelineRequest) -> None
    """Raise ServiceRequestError if the request URL is non-HTTPS and the sender did not specify enforce_https=False"""

    # move 'enforce_https' from options to context so it persists
    # across retries but isn't passed to a transport implementation
    option = request.context.options.pop("enforce_https", None)

    # True is the default setting; we needn't preserve an explicit opt in to the default behavior
    if option is False:
        request.context["enforce_https"] = option

    enforce_https = request.context.get("enforce_https", True)
    if enforce_https and not request.http_request.url.lower().startswith("https"):
        raise ServiceRequestError(
            "Bearer token authentication is not permitted for non-TLS protected (non-https) URLs."
        )
