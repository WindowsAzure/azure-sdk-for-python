# Stubs for azure.keyvault.keys._shared.challenge_auth_policy (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from .http_challenge import HttpChallenge
from azure.core.pipeline import PipelineRequest
from azure.core.pipeline.policies import HTTPPolicy
from azure.core.pipeline.policies.authentication import _BearerTokenCredentialPolicyBase
from azure.core.pipeline.transport import HttpResponse
from typing import Any

class ChallengeAuthPolicyBase(_BearerTokenCredentialPolicyBase):
    def __init__(self, credential: Any, **kwargs: Any) -> None: ...

class ChallengeAuthPolicy(ChallengeAuthPolicyBase, HTTPPolicy):
    def send(self, request: PipelineRequest) -> HttpResponse: ...
