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


class IdentityProviderBaseParameters(Model):
    """Identity Provider Base Parameter Properties.

    :param type: Identity Provider Type identifier. Possible values include:
     'facebook', 'google', 'microsoft', 'twitter', 'aad', 'aadB2C'
    :type type: str or ~azure.mgmt.apimanagement.models.IdentityProviderType
    :param signin_tenant: The TenantId to use instead of Common when logging
     into Active Directory
    :type signin_tenant: str
    :param allowed_tenants: List of Allowed Tenants when configuring Azure
     Active Directory login.
    :type allowed_tenants: list[str]
    :param authority: OpenID Connect discovery endpoint hostname for AAD or
     AAD B2C.
    :type authority: str
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
    """

    _validation = {
        'allowed_tenants': {'max_items': 32},
        'signup_policy_name': {'min_length': 1},
        'signin_policy_name': {'min_length': 1},
        'profile_editing_policy_name': {'min_length': 1},
        'password_reset_policy_name': {'min_length': 1},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'signin_tenant': {'key': 'signinTenant', 'type': 'str'},
        'allowed_tenants': {'key': 'allowedTenants', 'type': '[str]'},
        'authority': {'key': 'authority', 'type': 'str'},
        'signup_policy_name': {'key': 'signupPolicyName', 'type': 'str'},
        'signin_policy_name': {'key': 'signinPolicyName', 'type': 'str'},
        'profile_editing_policy_name': {'key': 'profileEditingPolicyName', 'type': 'str'},
        'password_reset_policy_name': {'key': 'passwordResetPolicyName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(IdentityProviderBaseParameters, self).__init__(**kwargs)
        self.type = kwargs.get('type', None)
        self.signin_tenant = kwargs.get('signin_tenant', None)
        self.allowed_tenants = kwargs.get('allowed_tenants', None)
        self.authority = kwargs.get('authority', None)
        self.signup_policy_name = kwargs.get('signup_policy_name', None)
        self.signin_policy_name = kwargs.get('signin_policy_name', None)
        self.profile_editing_policy_name = kwargs.get('profile_editing_policy_name', None)
        self.password_reset_policy_name = kwargs.get('password_reset_policy_name', None)
