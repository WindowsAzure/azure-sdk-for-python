# Stubs for azure.keyvault.keys._shared.async_challenge_auth_policy (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from . import ChallengeAuthPolicyBase
from azure.core.pipeline import PipelineRequest
from azure.core.pipeline.policies import AsyncHTTPPolicy
from azure.core.pipeline.transport import HttpResponse

class AsyncChallengeAuthPolicy(ChallengeAuthPolicyBase, AsyncHTTPPolicy):
    async def send(self, request: PipelineRequest) -> HttpResponse: ...
