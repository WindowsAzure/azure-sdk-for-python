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

from .resource import Resource


class AuthorizationServerUpdateContract(Resource):
    """External OAuth authorization server settings.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type for API Management resource.
    :vartype type: str
    :param description: Description of the authorization server. Can contain
     HTML formatting tags.
    :type description: str
    :param authorization_methods: HTTP verbs supported by the authorization
     endpoint. GET must be always present. POST is optional.
    :type authorization_methods: list[str or
     ~azure.mgmt.apimanagement.models.AuthorizationMethod]
    :param client_authentication_method: Method of authentication supported by
     the token endpoint of this authorization server. Possible values are Basic
     and/or Body. When Body is specified, client credentials and other
     parameters are passed within the request body in the
     application/x-www-form-urlencoded format.
    :type client_authentication_method: list[str or
     ~azure.mgmt.apimanagement.models.ClientAuthenticationMethod]
    :param token_body_parameters: Additional parameters required by the token
     endpoint of this authorization server represented as an array of JSON
     objects with name and value string properties, i.e. {"name" : "name
     value", "value": "a value"}.
    :type token_body_parameters:
     list[~azure.mgmt.apimanagement.models.TokenBodyParameterContract]
    :param token_endpoint: OAuth token endpoint. Contains absolute URI to
     entity being referenced.
    :type token_endpoint: str
    :param support_state: If true, authorization server will include state
     parameter from the authorization request to its response. Client may use
     state parameter to raise protocol security.
    :type support_state: bool
    :param default_scope: Access token scope that is going to be requested by
     default. Can be overridden at the API level. Should be provided in the
     form of a string containing space-delimited values.
    :type default_scope: str
    :param bearer_token_sending_methods: Specifies the mechanism by which
     access token is passed to the API.
    :type bearer_token_sending_methods: list[str or
     ~azure.mgmt.apimanagement.models.BearerTokenSendingMethod]
    :param client_secret: Client or app secret registered with this
     authorization server.
    :type client_secret: str
    :param resource_owner_username: Can be optionally specified when resource
     owner password grant type is supported by this authorization server.
     Default resource owner username.
    :type resource_owner_username: str
    :param resource_owner_password: Can be optionally specified when resource
     owner password grant type is supported by this authorization server.
     Default resource owner password.
    :type resource_owner_password: str
    :param display_name: User-friendly authorization server name.
    :type display_name: str
    :param client_registration_endpoint: Optional reference to a page where
     client or app registration for this authorization server is performed.
     Contains absolute URL to entity being referenced.
    :type client_registration_endpoint: str
    :param authorization_endpoint: OAuth authorization endpoint. See
     http://tools.ietf.org/html/rfc6749#section-3.2.
    :type authorization_endpoint: str
    :param grant_types: Form of an authorization grant, which the client uses
     to request the access token.
    :type grant_types: list[str or ~azure.mgmt.apimanagement.models.GrantType]
    :param client_id: Client or app id registered with this authorization
     server.
    :type client_id: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'display_name': {'max_length': 50, 'min_length': 1},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'authorization_methods': {'key': 'properties.authorizationMethods', 'type': '[AuthorizationMethod]'},
        'client_authentication_method': {'key': 'properties.clientAuthenticationMethod', 'type': '[str]'},
        'token_body_parameters': {'key': 'properties.tokenBodyParameters', 'type': '[TokenBodyParameterContract]'},
        'token_endpoint': {'key': 'properties.tokenEndpoint', 'type': 'str'},
        'support_state': {'key': 'properties.supportState', 'type': 'bool'},
        'default_scope': {'key': 'properties.defaultScope', 'type': 'str'},
        'bearer_token_sending_methods': {'key': 'properties.bearerTokenSendingMethods', 'type': '[str]'},
        'client_secret': {'key': 'properties.clientSecret', 'type': 'str'},
        'resource_owner_username': {'key': 'properties.resourceOwnerUsername', 'type': 'str'},
        'resource_owner_password': {'key': 'properties.resourceOwnerPassword', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'client_registration_endpoint': {'key': 'properties.clientRegistrationEndpoint', 'type': 'str'},
        'authorization_endpoint': {'key': 'properties.authorizationEndpoint', 'type': 'str'},
        'grant_types': {'key': 'properties.grantTypes', 'type': '[str]'},
        'client_id': {'key': 'properties.clientId', 'type': 'str'},
    }

    def __init__(self, *, description: str=None, authorization_methods=None, client_authentication_method=None, token_body_parameters=None, token_endpoint: str=None, support_state: bool=None, default_scope: str=None, bearer_token_sending_methods=None, client_secret: str=None, resource_owner_username: str=None, resource_owner_password: str=None, display_name: str=None, client_registration_endpoint: str=None, authorization_endpoint: str=None, grant_types=None, client_id: str=None, **kwargs) -> None:
        super(AuthorizationServerUpdateContract, self).__init__(, **kwargs)
        self.description = description
        self.authorization_methods = authorization_methods
        self.client_authentication_method = client_authentication_method
        self.token_body_parameters = token_body_parameters
        self.token_endpoint = token_endpoint
        self.support_state = support_state
        self.default_scope = default_scope
        self.bearer_token_sending_methods = bearer_token_sending_methods
        self.client_secret = client_secret
        self.resource_owner_username = resource_owner_username
        self.resource_owner_password = resource_owner_password
        self.display_name = display_name
        self.client_registration_endpoint = client_registration_endpoint
        self.authorization_endpoint = authorization_endpoint
        self.grant_types = grant_types
        self.client_id = client_id
