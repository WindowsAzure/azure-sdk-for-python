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

from .proxy_only_resource_py3 import ProxyOnlyResource


class SiteAuthSettings(ProxyOnlyResource):
    """Configuration settings for the Azure App Service Authentication /
    Authorization feature.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param enabled: <code>true</code> if the Authentication / Authorization
     feature is enabled for the current app; otherwise, <code>false</code>.
    :type enabled: bool
    :param runtime_version: The RuntimeVersion of the Authentication /
     Authorization feature in use for the current app.
     The setting in this value can control the behavior of certain features in
     the Authentication / Authorization module.
    :type runtime_version: str
    :param unauthenticated_client_action: The action to take when an
     unauthenticated client attempts to access the app. Possible values
     include: 'RedirectToLoginPage', 'AllowAnonymous'
    :type unauthenticated_client_action: str or
     ~azure.mgmt.web.models.UnauthenticatedClientAction
    :param token_store_enabled: <code>true</code> to durably store
     platform-specific security tokens that are obtained during login flows;
     otherwise, <code>false</code>.
     The default is <code>false</code>.
    :type token_store_enabled: bool
    :param allowed_external_redirect_urls: External URLs that can be
     redirected to as part of logging in or logging out of the app. Note that
     the query string part of the URL is ignored.
     This is an advanced setting typically only needed by Windows Store
     application backends.
     Note that URLs within the current domain are always implicitly allowed.
    :type allowed_external_redirect_urls: list[str]
    :param default_provider: The default authentication provider to use when
     multiple providers are configured.
     This setting is only needed if multiple providers are configured and the
     unauthenticated client
     action is set to "RedirectToLoginPage". Possible values include:
     'AzureActiveDirectory', 'Facebook', 'Google', 'MicrosoftAccount',
     'Twitter'
    :type default_provider: str or
     ~azure.mgmt.web.models.BuiltInAuthenticationProvider
    :param token_refresh_extension_hours: The number of hours after session
     token expiration that a session token can be used to
     call the token refresh API. The default is 72 hours.
    :type token_refresh_extension_hours: float
    :param client_id: The Client ID of this relying party application, known
     as the client_id.
     This setting is required for enabling OpenID Connection authentication
     with Azure Active Directory or
     other 3rd party OpenID Connect providers.
     More information on OpenID Connect:
     http://openid.net/specs/openid-connect-core-1_0.html
    :type client_id: str
    :param client_secret: The Client Secret of this relying party application
     (in Azure Active Directory, this is also referred to as the Key).
     This setting is optional. If no client secret is configured, the OpenID
     Connect implicit auth flow is used to authenticate end users.
     Otherwise, the OpenID Connect Authorization Code Flow is used to
     authenticate end users.
     More information on OpenID Connect:
     http://openid.net/specs/openid-connect-core-1_0.html
    :type client_secret: str
    :param issuer: The OpenID Connect Issuer URI that represents the entity
     which issues access tokens for this application.
     When using Azure Active Directory, this value is the URI of the directory
     tenant, e.g. https://sts.windows.net/{tenant-guid}/.
     This URI is a case-sensitive identifier for the token issuer.
     More information on OpenID Connect Discovery:
     http://openid.net/specs/openid-connect-discovery-1_0.html
    :type issuer: str
    :param validate_issuer: Gets a value indicating whether the issuer should
     be a valid HTTPS url and be validated as such.
    :type validate_issuer: bool
    :param allowed_audiences: Allowed audience values to consider when
     validating JWTs issued by
     Azure Active Directory. Note that the <code>ClientID</code> value is
     always considered an
     allowed audience, regardless of this setting.
    :type allowed_audiences: list[str]
    :param additional_login_params: Login parameters to send to the OpenID
     Connect authorization endpoint when
     a user logs in. Each parameter must be in the form "key=value".
    :type additional_login_params: list[str]
    :param google_client_id: The OpenID Connect Client ID for the Google web
     application.
     This setting is required for enabling Google Sign-In.
     Google Sign-In documentation:
     https://developers.google.com/identity/sign-in/web/
    :type google_client_id: str
    :param google_client_secret: The client secret associated with the Google
     web application.
     This setting is required for enabling Google Sign-In.
     Google Sign-In documentation:
     https://developers.google.com/identity/sign-in/web/
    :type google_client_secret: str
    :param google_oauth_scopes: The OAuth 2.0 scopes that will be requested as
     part of Google Sign-In authentication.
     This setting is optional. If not specified, "openid", "profile", and
     "email" are used as default scopes.
     Google Sign-In documentation:
     https://developers.google.com/identity/sign-in/web/
    :type google_oauth_scopes: list[str]
    :param facebook_app_id: The App ID of the Facebook app used for login.
     This setting is required for enabling Facebook Login.
     Facebook Login documentation:
     https://developers.facebook.com/docs/facebook-login
    :type facebook_app_id: str
    :param facebook_app_secret: The App Secret of the Facebook app used for
     Facebook Login.
     This setting is required for enabling Facebook Login.
     Facebook Login documentation:
     https://developers.facebook.com/docs/facebook-login
    :type facebook_app_secret: str
    :param facebook_oauth_scopes: The OAuth 2.0 scopes that will be requested
     as part of Facebook Login authentication.
     This setting is optional.
     Facebook Login documentation:
     https://developers.facebook.com/docs/facebook-login
    :type facebook_oauth_scopes: list[str]
    :param twitter_consumer_key: The OAuth 1.0a consumer key of the Twitter
     application used for sign-in.
     This setting is required for enabling Twitter Sign-In.
     Twitter Sign-In documentation: https://dev.twitter.com/web/sign-in
    :type twitter_consumer_key: str
    :param twitter_consumer_secret: The OAuth 1.0a consumer secret of the
     Twitter application used for sign-in.
     This setting is required for enabling Twitter Sign-In.
     Twitter Sign-In documentation: https://dev.twitter.com/web/sign-in
    :type twitter_consumer_secret: str
    :param microsoft_account_client_id: The OAuth 2.0 client ID that was
     created for the app used for authentication.
     This setting is required for enabling Microsoft Account authentication.
     Microsoft Account OAuth documentation:
     https://dev.onedrive.com/auth/msa_oauth.htm
    :type microsoft_account_client_id: str
    :param microsoft_account_client_secret: The OAuth 2.0 client secret that
     was created for the app used for authentication.
     This setting is required for enabling Microsoft Account authentication.
     Microsoft Account OAuth documentation:
     https://dev.onedrive.com/auth/msa_oauth.htm
    :type microsoft_account_client_secret: str
    :param microsoft_account_oauth_scopes: The OAuth 2.0 scopes that will be
     requested as part of Microsoft Account authentication.
     This setting is optional. If not specified, "wl.basic" is used as the
     default scope.
     Microsoft Account Scopes and permissions documentation:
     https://msdn.microsoft.com/en-us/library/dn631845.aspx
    :type microsoft_account_oauth_scopes: list[str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'runtime_version': {'key': 'properties.runtimeVersion', 'type': 'str'},
        'unauthenticated_client_action': {'key': 'properties.unauthenticatedClientAction', 'type': 'UnauthenticatedClientAction'},
        'token_store_enabled': {'key': 'properties.tokenStoreEnabled', 'type': 'bool'},
        'allowed_external_redirect_urls': {'key': 'properties.allowedExternalRedirectUrls', 'type': '[str]'},
        'default_provider': {'key': 'properties.defaultProvider', 'type': 'BuiltInAuthenticationProvider'},
        'token_refresh_extension_hours': {'key': 'properties.tokenRefreshExtensionHours', 'type': 'float'},
        'client_id': {'key': 'properties.clientId', 'type': 'str'},
        'client_secret': {'key': 'properties.clientSecret', 'type': 'str'},
        'issuer': {'key': 'properties.issuer', 'type': 'str'},
        'validate_issuer': {'key': 'properties.validateIssuer', 'type': 'bool'},
        'allowed_audiences': {'key': 'properties.allowedAudiences', 'type': '[str]'},
        'additional_login_params': {'key': 'properties.additionalLoginParams', 'type': '[str]'},
        'google_client_id': {'key': 'properties.googleClientId', 'type': 'str'},
        'google_client_secret': {'key': 'properties.googleClientSecret', 'type': 'str'},
        'google_oauth_scopes': {'key': 'properties.googleOAuthScopes', 'type': '[str]'},
        'facebook_app_id': {'key': 'properties.facebookAppId', 'type': 'str'},
        'facebook_app_secret': {'key': 'properties.facebookAppSecret', 'type': 'str'},
        'facebook_oauth_scopes': {'key': 'properties.facebookOAuthScopes', 'type': '[str]'},
        'twitter_consumer_key': {'key': 'properties.twitterConsumerKey', 'type': 'str'},
        'twitter_consumer_secret': {'key': 'properties.twitterConsumerSecret', 'type': 'str'},
        'microsoft_account_client_id': {'key': 'properties.microsoftAccountClientId', 'type': 'str'},
        'microsoft_account_client_secret': {'key': 'properties.microsoftAccountClientSecret', 'type': 'str'},
        'microsoft_account_oauth_scopes': {'key': 'properties.microsoftAccountOAuthScopes', 'type': '[str]'},
    }

    def __init__(self, *, kind: str=None, enabled: bool=None, runtime_version: str=None, unauthenticated_client_action=None, token_store_enabled: bool=None, allowed_external_redirect_urls=None, default_provider=None, token_refresh_extension_hours: float=None, client_id: str=None, client_secret: str=None, issuer: str=None, validate_issuer: bool=None, allowed_audiences=None, additional_login_params=None, google_client_id: str=None, google_client_secret: str=None, google_oauth_scopes=None, facebook_app_id: str=None, facebook_app_secret: str=None, facebook_oauth_scopes=None, twitter_consumer_key: str=None, twitter_consumer_secret: str=None, microsoft_account_client_id: str=None, microsoft_account_client_secret: str=None, microsoft_account_oauth_scopes=None, **kwargs) -> None:
        super(SiteAuthSettings, self).__init__(kind=kind, **kwargs)
        self.enabled = enabled
        self.runtime_version = runtime_version
        self.unauthenticated_client_action = unauthenticated_client_action
        self.token_store_enabled = token_store_enabled
        self.allowed_external_redirect_urls = allowed_external_redirect_urls
        self.default_provider = default_provider
        self.token_refresh_extension_hours = token_refresh_extension_hours
        self.client_id = client_id
        self.client_secret = client_secret
        self.issuer = issuer
        self.validate_issuer = validate_issuer
        self.allowed_audiences = allowed_audiences
        self.additional_login_params = additional_login_params
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
