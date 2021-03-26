# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

from enum import Enum

from ._async_authentication_policy import ContainerRegistryChallengePolicy
from .._generated.aio import ContainerRegistry
from .._user_agent import USER_AGENT


class ContainerRegistryApiVersion(str, Enum):
    """Container Registry API version supported by this package"""

    V0_PREVIEW = ""


class ContainerRegistryBaseClient(object):
    """Base class for ContainerRegistryClient and ContainerRepositoryClient

    :param endpoint: Azure Container Registry endpoint
    :type endpoint: str
    :param credential: AAD Token for authenticating requests with Azure
    :type credential: :class:`azure.identity.DefaultTokenCredential`

    """

    def __init__(self, endpoint, credential, **kwargs):  # pylint:disable=client-method-missing-type-annotations
        auth_policy = ContainerRegistryChallengePolicy(credential, endpoint)
        self._client = ContainerRegistry(
            credential=credential,
            url=endpoint,
            sdk_moniker=USER_AGENT,
            authentication_policy=auth_policy,
            credential_scopes=kwargs.pop("credential_scopes", ["https://management.core.windows.net/.default"]),
            **kwargs
        )

    async def __aenter__(self):
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args):
        await self._client.__aexit__(*args)

    def close(self):
        # type: () -> None
        """Close sockets opened by the client.
        Calling this method is unnecessary when using the client as a context manager.
        """
        self._client.close()

    def _is_tag(self, tag_or_digest):  # pylint: disable=no-self-use
        tag = tag_or_digest.split(":")
        return not (len(tag) == 2 and tag[0].startswith(u"sha"))