# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import abc
import os
from typing import TYPE_CHECKING

from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.core.pipeline.policies import AsyncRetryPolicy

from azure.identity._credentials.managed_identity import _ManagedIdentityBase
from .base import AsyncCredentialBase
from .._authn_client import AsyncAuthnClient
from ... import CredentialUnavailableError
from ..._constants import Endpoints, EnvironmentVariables

if TYPE_CHECKING:
    from typing import Any, Optional
    from azure.core.configuration import Configuration


class ManagedIdentityCredential(AsyncCredentialBase):
    """Authenticates with an Azure managed identity in any hosting environment which supports managed identities.

    This credential defaults to using a system-assigned identity. Use the `client_id` keyword argument to specify a
    user-assigned identity.

    :keyword str client_id: optional identifier of a user-assigned identity. Typically this should be the identity's
        client ID. To configure an identity using another identifier, specify the appropriate parameter name for your
        hosting environment in `client_id_type`.
    :keyword str client_id_type: the managed identity parameter name for the value of `client_id`. Useful only when
        that value is the identity's object or Azure Resource ID. Valid values vary by hosting environment. Consult
        your hosting environment's documentation to determine what parameter names it expects.
    """

    def __init__(self, **kwargs: "Any") -> None:
        self._credential = None
        if os.environ.get(EnvironmentVariables.MSI_ENDPOINT):
            self._credential = MsiCredential(**kwargs)
        else:
            self._credential = ImdsCredential(**kwargs)

    async def __aenter__(self):
        if self._credential:
            await self._credential.__aenter__()
        return self

    async def close(self):
        """Close the credential's transport session."""
        if self._credential:
            await self._credential.__aexit__()

    async def get_token(self, *scopes: str, **kwargs: "Any") -> "AccessToken":
        """Asynchronously request an access token for `scopes`.

        .. note:: This method is called by Azure SDK clients. It isn't intended for use in application code.

        :param str scopes: desired scope for the access token. This credential allows only one scope per request.
        :rtype: :class:`azure.core.credentials.AccessToken`
        :raises ~azure.identity.CredentialUnavailableError: managed identity isn't available in the hosting environment
        """
        if not self._credential:
            raise CredentialUnavailableError(message="No managed identity endpoint found.")
        return await self._credential.get_token(*scopes, **kwargs)


class _AsyncManagedIdentityBase(_ManagedIdentityBase, AsyncCredentialBase):
    def __init__(self, endpoint: str, **kwargs: "Any") -> None:
        super().__init__(endpoint=endpoint, client_cls=AsyncAuthnClient, **kwargs)

    async def __aenter__(self):
        await self._client.__aenter__()
        return self

    async def close(self):
        """Close the credential's transport session."""

        await self._client.__aexit__()

    @abc.abstractmethod
    async def get_token(self, *scopes, **kwargs):
        pass

    @staticmethod
    def _create_config(**kwargs: "Any") -> "Configuration":
        """Build a default configuration for the credential's HTTP pipeline."""
        return _ManagedIdentityBase._create_config(retry_policy=AsyncRetryPolicy, **kwargs)


class ImdsCredential(_AsyncManagedIdentityBase):
    """Asynchronously authenticates with a managed identity via the IMDS endpoint.

    :keyword str client_id: ID of a user-assigned identity. Leave unspecified to use a system-assigned identity.
    """

    def __init__(self, **kwargs: "Any") -> None:
        super().__init__(endpoint=Endpoints.IMDS, **kwargs)
        self._endpoint_available = None  # type: Optional[bool]

    async def get_token(self, *scopes: str, **kwargs: "Any") -> AccessToken:  # pylint:disable=unused-argument
        """Asynchronously request an access token for `scopes`.

        .. note:: This method is called by Azure SDK clients. It isn't intended for use in application code.

        :param str scopes: desired scope for the access token. This credential allows only one scope per request.
        :rtype: :class:`azure.core.credentials.AccessToken`
        :raises ~azure.identity.CredentialUnavailableError: the IMDS endpoint is unreachable
        """
        if self._endpoint_available is None:
            # Lacking another way to determine whether the IMDS endpoint is listening,
            # we send a request it would immediately reject (missing a required header),
            # setting a short timeout.
            try:
                await self._client.request_token(scopes, method="GET", connection_timeout=0.3, retry_total=0)
                self._endpoint_available = True
            except HttpResponseError:
                # received a response, choked on it
                self._endpoint_available = True
            except Exception:  # pylint:disable=broad-except
                # if anything else was raised, assume the endpoint is unavailable
                self._endpoint_available = False

        if not self._endpoint_available:
            message = "ManagedIdentityCredential authentication unavailable, no managed identity endpoint found."
            raise CredentialUnavailableError(message=message)

        if len(scopes) != 1:
            raise ValueError("This credential requires exactly one scope per token request.")

        token = self._client.get_cached_token(scopes)
        if not token:
            resource = scopes[0]
            if resource.endswith("/.default"):
                resource = resource[: -len("/.default")]
            params = {"api-version": "2018-02-01", "resource": resource, **self._user_assigned_identity}

            try:
                token = await self._client.request_token(scopes, method="GET", params=params)
            except HttpResponseError as ex:
                # 400 in response to a token request indicates managed identity is disabled,
                # or the identity with the specified client_id is not available
                if ex.status_code == 400:
                    self._endpoint_available = False
                    message = "ManagedIdentityCredential authentication unavailable. "
                    if self._user_assigned_identity:
                        message += "The requested identity has not been assigned to this resource."
                    else:
                        message += "No identity has been assigned to this resource."
                    raise CredentialUnavailableError(message=message) from ex

                # any other error is unexpected
                raise ClientAuthenticationError(message=ex.message, response=ex.response) from None

        return token


class MsiCredential(_AsyncManagedIdentityBase):
    """Authenticates via the MSI endpoint in an App Service or Cloud Shell environment.

    :keyword str client_id: ID of a user-assigned identity. Leave unspecified to use a system-assigned identity.
    """

    def __init__(self, **kwargs: "Any") -> None:
        self._endpoint = os.environ.get(EnvironmentVariables.MSI_ENDPOINT)
        if self._endpoint:
            super().__init__(endpoint=self._endpoint, **kwargs)

    async def get_token(self, *scopes: str, **kwargs: "Any") -> AccessToken:  # pylint:disable=unused-argument
        """Asynchronously request an access token for `scopes`.

        .. note:: This method is called by Azure SDK clients. It isn't intended for use in application code.

        :param str scopes: desired scope for the access token. This credential allows only one scope per request.
        :rtype: :class:`azure.core.credentials.AccessToken`
        :raises ~azure.identity.CredentialUnavailableError: the MSI endpoint is unavailable
        """
        if not self._endpoint:
            message = "ManagedIdentityCredential authentication unavailable, no managed identity endpoint found."
            raise CredentialUnavailableError(message=message)

        if len(scopes) != 1:
            raise ValueError("This credential requires exactly one scope per token request.")

        token = self._client.get_cached_token(scopes)
        if not token:
            resource = scopes[0]
            if resource.endswith("/.default"):
                resource = resource[: -len("/.default")]

            secret = os.environ.get(EnvironmentVariables.MSI_SECRET)
            if secret:
                # MSI_ENDPOINT and MSI_SECRET set -> App Service
                token = await self._request_app_service_token(scopes=scopes, resource=resource, secret=secret)
            else:
                # only MSI_ENDPOINT set -> legacy-style MSI (Cloud Shell)
                token = await self._request_legacy_token(scopes=scopes, resource=resource)
        return token

    async def _request_app_service_token(self, scopes, resource, secret):
        params = {"api-version": "2017-09-01", "resource": resource, **self._user_assigned_identity}
        return await self._client.request_token(scopes, method="GET", headers={"secret": secret}, params=params)

    async def _request_legacy_token(self, scopes, resource):
        form_data = {"resource": resource, **self._user_assigned_identity}
        return await self._client.request_token(scopes, method="POST", form_data=form_data)
