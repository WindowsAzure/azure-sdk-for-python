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


class IdentityProviderContract(Resource):
    """Identity Provider details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type for API Management resource.
    :vartype type: str
    :param identity_provider_contract_type: Identity Provider Type identifier.
     Possible values include: 'facebook', 'google', 'microsoft', 'twitter',
     'aad', 'aadB2C'
    :type identity_provider_contract_type: str or
     ~azure.mgmt.apimanagement.models.IdentityProviderType
    :param allowed_tenants: List of Allowed Tenants when configuring Azure
     Active Directory login.
    :type allowed_tenants: list[str]
    :param signup_policy_name: Signup Policy Name. Only applies to AAD B2C
     Identity Provider.
    :type signup_policy_name: str
    :param signin_policy_name: Signin Policy Name. Only applies to AAD B2C
     Identity Provider.
    :type signin_policy_name: str
    :param profile_editing_policy_name: Profile Editing Policy Name. Only
     applies to AAD B2C Identity Provider.
    :type profile_editing_policy_name: str
    :param password_reset_policy_name: Password Reset Policy Name. Only
     applies to AAD B2C Identity Provider.
    :type password_reset_policy_name: str
    :param client_id: Required. Client Id of the Application in the external
     Identity Provider. It is App ID for Facebook login, Client ID for Google
     login, App ID for Microsoft.
    :type client_id: str
    :param client_secret: Required. Client secret of the Application in
     external Identity Provider, used to authenticate login request. For
     example, it is App Secret for Facebook login, API Key for Google login,
     Public Key for Microsoft.
    :type client_secret: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'allowed_tenants': {'max_items': 32},
        'signup_policy_name': {'min_length': 1},
        'signin_policy_name': {'min_length': 1},
        'profile_editing_policy_name': {'min_length': 1},
        'password_reset_policy_name': {'min_length': 1},
        'client_id': {'required': True, 'min_length': 1},
        'client_secret': {'required': True, 'min_length': 1},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'identity_provider_contract_type': {'key': 'properties.type', 'type': 'str'},
        'allowed_tenants': {'key': 'properties.allowedTenants', 'type': '[str]'},
        'signup_policy_name': {'key': 'properties.signupPolicyName', 'type': 'str'},
        'signin_policy_name': {'key': 'properties.signinPolicyName', 'type': 'str'},
        'profile_editing_policy_name': {'key': 'properties.profileEditingPolicyName', 'type': 'str'},
        'password_reset_policy_name': {'key': 'properties.passwordResetPolicyName', 'type': 'str'},
        'client_id': {'key': 'properties.clientId', 'type': 'str'},
        'client_secret': {'key': 'properties.clientSecret', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(IdentityProviderContract, self).__init__(**kwargs)
        self.identity_provider_contract_type = kwargs.get('identity_provider_contract_type', None)
        self.allowed_tenants = kwargs.get('allowed_tenants', None)
        self.signup_policy_name = kwargs.get('signup_policy_name', None)
        self.signin_policy_name = kwargs.get('signin_policy_name', None)
        self.profile_editing_policy_name = kwargs.get('profile_editing_policy_name', None)
        self.password_reset_policy_name = kwargs.get('password_reset_policy_name', None)
        self.client_id = kwargs.get('client_id', None)
        self.client_secret = kwargs.get('client_secret', None)
