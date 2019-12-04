# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from azure.core.pipeline import PipelineRequest
from azure.core.pipeline.policies import AsyncHTTPPolicy
from azure.core.pipeline.transport import HttpResponse

from . import ChallengeAuthPolicyBase, HttpChallenge, HttpChallengeCache


class AsyncChallengeAuthPolicy(ChallengeAuthPolicyBase, AsyncHTTPPolicy):
    """policy for handling HTTP authentication challenges"""

    async def send(self, request: PipelineRequest) -> HttpResponse:
        challenge = HttpChallengeCache.get_challenge_for_url(request.http_request.url)
        if not challenge:
            challenge_request = self._get_challenge_request(request)
            challenger = await self.next.send(challenge_request)
            try:
                challenge = self._update_challenge(request, challenger)
            except ValueError:
                # didn't receive the expected challenge -> nothing more this policy can do
                return challenger

        await self._handle_challenge(request, challenge)
        response = await self.next.send(request)

        if response.http_response.status_code == 401:
            # any cached token must be invalid
            self._token = None

            # cached challenge could be outdated; maybe this response has a new one?
            try:
                challenge = self._update_challenge(request, response)
            except ValueError:
                # 401 with no legible challenge -> nothing more this policy can do
                return response

            await self._handle_challenge(request, challenge)
            response = await self.next.send(request)

        return response

    async def _handle_challenge(self, request: PipelineRequest, challenge: HttpChallenge) -> None:
        """authenticate according to challenge, add Authorization header to request"""

        scope = challenge.get_resource()
        if not scope.endswith("/.default"):
            scope += "/.default"

        if self._need_new_token:
            self._token = await self._credential.get_token(scope)

        # ignore mypy's warning because although self._token is Optional, get_token raises when it fails to get a token
        self._update_headers(request.http_request.headers, self._token.token)  # type: ignore
