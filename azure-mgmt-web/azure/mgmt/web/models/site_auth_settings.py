# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class SiteAuthSettings(Model):
    """Configuration settings for the Azure App Service Authentication /
    Authorization feature.

    :param enabled: Gets or sets a value indicating whether the Authentication
     / Authorization feature is enabled for the current app.
    :type enabled: bool
    :param http_api_prefix_path: Gets or sets the relative path prefix used by
     platform HTTP APIs.
     Changing this value is not recommended except for compatibility reasons.
    :type http_api_prefix_path: str
    :param unauthenticated_client_action: Gets or sets the action to take when
     an unauthenticated client attempts to access the app. Possible values
     include: 'RedirectToLoginPage', 'AllowAnonymous'
    :type unauthenticated_client_action: str or
     :class:`UnauthenticatedClientAction
     <azure.mgmt.web.models.UnauthenticatedClientAction>`
    :param token_store_enabled: Gets or sets a value indicating whether to
     durably store platform-specific security tokens
     obtained during login flows. This capability is disabled by default.
    :type token_store_enabled: bool
    :param allowed_external_redirect_urls: Gets or sets a collection of
     external URLs that can be redirected to as part of logging in
     or logging out of the web app. Note that the query string part of the URL
     is ignored.
     This is an advanced setting typically only needed by Windows Store
     application backends.
     Note that URLs within the current domain are always implicitly allowed.
    :type allowed_external_redirect_urls: list of str
    :param default_provider: Gets or sets the default authentication provider
     to use when multiple providers are configured.
     This setting is only needed if multiple providers are configured and the
     unauthenticated client
     action is set to "RedirectToLoginPage". Possible values include:
     'AzureActiveDirectory', 'Facebook', 'Google', 'MicrosoftAccount',
     'Twitter'
    :type default_provider: str or :class:`BuiltInAuthenticationProvider
     <azure.mgmt.web.models.BuiltInAuthenticationProvider>`
    :param token_refresh_extension_hours: Gets or sets the number of hours
     after session token expiration that a session token can be used to
     call the token refresh API. The default is 72 hours.
    :type token_refresh_extension_hours: float
    :param client_id: Gets or sets the Client ID of this relying party
     application, known as the client_id.
     This setting is required for enabling OpenID Connection authentication
     with Azure Active Directory or
     other 3rd party OpenID Connect providers.
     More information on OpenID Connect:
     http://openid.net/specs/openid-connect-core-1_0.html
    :type client_id: str
    :param client_secret: Gets or sets the Client Secret of this relying party
     application (in Azure Active Directory, this is also referred to as the
     Key).
     This setting is optional. If no client secret is configured, the OpenID
     Connect implicit auth flow is used to authenticate end users.
     Otherwise, the OpenID Connect Authorization Code Flow is used to
     authenticate end users.
     More information on OpenID Connect:
     http://openid.net/specs/openid-connect-core-1_0.html
    :type client_secret: str
    :param issuer: Gets or sets the OpenID Connect Issuer URI that represents
     the entity which issues access tokens for this application.
     When using Azure Active Directory, this value is the URI of the directory
     tenant, e.g. https://sts.windows.net/{tenant-guid}/.
     This URI is a case-sensitive identifier for the token issuer.
     More information on OpenID Connect Discovery:
     http://openid.net/specs/openid-connect-discovery-1_0.html
    :type issuer: str
    :param allowed_audiences: Gets or sets a list of allowed audience values
     to consider when validating JWTs issued by
     Azure Active Directory. Note that the
     {Microsoft.Web.Hosting.Administration.SiteAuthSettings.ClientId} value is
     always considered an
     allowed audience, regardless of this setting.
    :type allowed_audiences: list of str
    :param additional_login_params: Gets or sets a list of login parameters to
     send to the OpenID Connect authorization endpoint when
     a user logs in. Each parameter must be in the form "key=value".
    :type additional_login_params: list of str
    :param aad_client_id:
    :type aad_client_id: str
    :param open_id_issuer:
    :type open_id_issuer: str
    :param google_client_id: Gets or sets the OpenID Connect Client ID for the
     Google web application.
     This setting is required for enabling Google Sign-In.
     Google Sign-In documentation:
     https://developers.google.com/identity/sign-in/web/
    :type google_client_id: str
    :param google_client_secret: Gets or sets the client secret associated
     with the Google web application.
     This setting is required for enabling Google Sign-In.
     Google Sign-In documentation:
     https://developers.google.com/identity/sign-in/web/
    :type google_client_secret: str
    :param google_oauth_scopes: Gets or sets the OAuth 2.0 scopes that will be
     requested as part of Google Sign-In authentication.
     This setting is optional. If not specified, "openid", "profile", and
     "email" are used as default scopes.
     Google Sign-In documentation:
     https://developers.google.com/identity/sign-in/web/
    :type google_oauth_scopes: list of str
    :param facebook_app_id: Gets or sets the App ID of the Facebook app used
     for login.
     This setting is required for enabling Facebook Login.
     Facebook Login documentation:
     https://developers.facebook.com/docs/facebook-login
    :type facebook_app_id: str
    :param facebook_app_secret: Gets or sets the App Secret of the Facebook
     app used for Facebook Login.
     This setting is required for enabling Facebook Login.
     Facebook Login documentation:
     https://developers.facebook.com/docs/facebook-login
    :type facebook_app_secret: str
    :param facebook_oauth_scopes: Gets or sets the OAuth 2.0 scopes that will
     be requested as part of Facebook Login authentication.
     This setting is optional.
     Facebook Login documentation:
     https://developers.facebook.com/docs/facebook-login
    :type facebook_oauth_scopes: list of str
    :param twitter_consumer_key: Gets or sets the OAuth 1.0a consumer key of
     the Twitter application used for sign-in.
     This setting is required for enabling Twitter Sign-In.
     Twitter Sign-In documentation: https://dev.twitter.com/web/sign-in
    :type twitter_consumer_key: str
    :param twitter_consumer_secret: Gets or sets the OAuth 1.0a consumer
     secret of the Twitter application used for sign-in.
     This setting is required for enabling Twitter Sign-In.
     Twitter Sign-In documentation: https://dev.twitter.com/web/sign-in
    :type twitter_consumer_secret: str
    :param microsoft_account_client_id: Gets or sets the OAuth 2.0 client ID
     that was created for the app used for authentication.
     This setting is required for enabling Microsoft Account authentication.
     Microsoft Account OAuth documentation:
     https://dev.onedrive.com/auth/msa_oauth.htm
    :type microsoft_account_client_id: str
    :param microsoft_account_client_secret: Gets or sets the OAuth 2.0 client
     secret that was created for the app used for authentication.
     This setting is required for enabling Microsoft Account authentication.
     Microsoft Account OAuth documentation:
     https://dev.onedrive.com/auth/msa_oauth.htm
    :type microsoft_account_client_secret: str
    :param microsoft_account_oauth_scopes: Gets or sets the OAuth 2.0 scopes
     that will be requested as part of Microsoft Account authentication.
     This setting is optional. If not specified, "wl.basic" is used as the
     default scope.
     Microsoft Account Scopes and permissions documentation:
     https://msdn.microsoft.com/en-us/library/dn631845.aspx
    :type microsoft_account_oauth_scopes: list of str
    """

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'http_api_prefix_path': {'key': 'httpApiPrefixPath', 'type': 'str'},
        'unauthenticated_client_action': {'key': 'unauthenticatedClientAction', 'type': 'UnauthenticatedClientAction'},
        'token_store_enabled': {'key': 'tokenStoreEnabled', 'type': 'bool'},
        'allowed_external_redirect_urls': {'key': 'allowedExternalRedirectUrls', 'type': '[str]'},
        'default_provider': {'key': 'defaultProvider', 'type': 'BuiltInAuthenticationProvider'},
        'token_refresh_extension_hours': {'key': 'tokenRefreshExtensionHours', 'type': 'float'},
        'client_id': {'key': 'clientId', 'type': 'str'},
        'client_secret': {'key': 'clientSecret', 'type': 'str'},
        'issuer': {'key': 'issuer', 'type': 'str'},
        'allowed_audiences': {'key': 'allowedAudiences', 'type': '[str]'},
        'additional_login_params': {'key': 'additionalLoginParams', 'type': '[str]'},
        'aad_client_id': {'key': 'aadClientId', 'type': 'str'},
        'open_id_issuer': {'key': 'openIdIssuer', 'type': 'str'},
        'google_client_id': {'key': 'googleClientId', 'type': 'str'},
        'google_client_secret': {'key': 'googleClientSecret', 'type': 'str'},
        'google_oauth_scopes': {'key': 'googleOAuthScopes', 'type': '[str]'},
        'facebook_app_id': {'key': 'facebookAppId', 'type': 'str'},
        'facebook_app_secret': {'key': 'facebookAppSecret', 'type': 'str'},
        'facebook_oauth_scopes': {'key': 'facebookOAuthScopes', 'type': '[str]'},
        'twitter_consumer_key': {'key': 'twitterConsumerKey', 'type': 'str'},
        'twitter_consumer_secret': {'key': 'twitterConsumerSecret', 'type': 'str'},
        'microsoft_account_client_id': {'key': 'microsoftAccountClientId', 'type': 'str'},
        'microsoft_account_client_secret': {'key': 'microsoftAccountClientSecret', 'type': 'str'},
        'microsoft_account_oauth_scopes': {'key': 'microsoftAccountOAuthScopes', 'type': '[str]'},
    }

    def __init__(self, enabled=None, http_api_prefix_path=None, unauthenticated_client_action=None, token_store_enabled=None, allowed_external_redirect_urls=None, default_provider=None, token_refresh_extension_hours=None, client_id=None, client_secret=None, issuer=None, allowed_audiences=None, additional_login_params=None, aad_client_id=None, open_id_issuer=None, google_client_id=None, google_client_secret=None, google_oauth_scopes=None, facebook_app_id=None, facebook_app_secret=None, facebook_oauth_scopes=None, twitter_consumer_key=None, twitter_consumer_secret=None, microsoft_account_client_id=None, microsoft_account_client_secret=None, microsoft_account_oauth_scopes=None):
        self.enabled = enabled
        self.http_api_prefix_path = http_api_prefix_path
        self.unauthenticated_client_action = unauthenticated_client_action
        self.token_store_enabled = token_store_enabled
        self.allowed_external_redirect_urls = allowed_external_redirect_urls
        self.default_provider = default_provider
        self.token_refresh_extension_hours = token_refresh_extension_hours
        self.client_id = client_id
        self.client_secret = client_secret
        self.issuer = issuer
        self.allowed_audiences = allowed_audiences
        self.additional_login_params = additional_login_params
        self.aad_client_id = aad_client_id
        self.open_id_issuer = open_id_issuer
        self.google_client_id = google_client_id
        self.google_client_secret = google_client_secret
        self.google_oauth_scopes = google_oauth_scopes
        self.facebook_app_id = facebook_app_id
        self.facebook_app_secret = facebook_app_secret
        self.facebook_oauth_scopes = facebook_oauth_scopes
        self.twitter_consumer_key = twitter_consumer_key
        self.twitter_consumer_secret = twitter_consumer_secret
        self.microsoft_account_client_id = microsoft_account_client_id
        self.microsoft_account_client_secret = microsoft_account_client_secret
        self.microsoft_account_oauth_scopes = microsoft_account_oauth_scopes
