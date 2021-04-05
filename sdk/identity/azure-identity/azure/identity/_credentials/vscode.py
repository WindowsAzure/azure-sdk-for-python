# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import sys
from typing import TYPE_CHECKING

from .._exceptions import CredentialUnavailableError
from .._constants import AZURE_VSCODE_CLIENT_ID
from .._internal import validate_tenant_id
from .._internal.aad_client import AadClient
from .._internal.get_token_mixin import GetTokenMixin

if sys.platform.startswith("win"):
    from .._internal.win_vscode_adapter import get_credentials
elif sys.platform.startswith("darwin"):
    from .._internal.macos_vscode_adapter import get_credentials
else:
    from .._internal.linux_vscode_adapter import get_credentials

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from typing import Any, Optional
    from azure.core.credentials import AccessToken


class VisualStudioCodeCredential(GetTokenMixin):
    """Authenticates as the Azure user signed in to Visual Studio Code.

    :keyword str authority: Authority of an Azure Active Directory endpoint, for example 'login.microsoftonline.com',
          the authority for Azure Public Cloud (which is the default). :class:`~azure.identity.AzureAuthorityHosts`
          defines authorities for other clouds.
    :keyword str tenant_id: ID of the tenant the credential should authenticate in. Defaults to the "organizations"
        tenant, which supports only Azure Active Directory work or school accounts.
    """

    def __init__(self, **kwargs):
        # type: (**Any) -> None
        super(VisualStudioCodeCredential, self).__init__()
        self._refresh_token = None
        self._client = kwargs.pop("_client", None)
        self._tenant_id = kwargs.pop("tenant_id", None) or "organizations"
        validate_tenant_id(self._tenant_id)
        if not self._client:
            self._client = AadClient(self._tenant_id, AZURE_VSCODE_CLIENT_ID, **kwargs)

    def get_token(self, *scopes, **kwargs):
        # type: (*str, **Any) -> AccessToken
        """Request an access token for `scopes` as the user currently signed in to Visual Studio Code.

        This method is called automatically by Azure SDK clients.

        :param str scopes: desired scopes for the access token. This method requires at least one scope.
        :rtype: :class:`azure.core.credentials.AccessToken`
        :raises ~azure.identity.CredentialUnavailableError: the credential cannot retrieve user details from Visual
          Studio Code
        """
        if self._tenant_id.lower() == "adfs":
            raise CredentialUnavailableError(
                message="VisualStudioCodeCredential authentication unavailable. ADFS is not supported."
            )
        return super(VisualStudioCodeCredential, self).get_token(*scopes, **kwargs)

    def _acquire_token_silently(self, *scopes):
        # type: (*str) -> Optional[AccessToken]
        return self._client.get_cached_access_token(scopes)

    def _request_token(self, *scopes, **kwargs):
        # type: (*str, **Any) -> AccessToken
        if not self._refresh_token:
            self._refresh_token = get_credentials()
            if not self._refresh_token:
                raise CredentialUnavailableError(message="Failed to get Azure user details from Visual Studio Code.")

        return self._client.obtain_token_by_refresh_token(scopes, self._refresh_token, **kwargs)
