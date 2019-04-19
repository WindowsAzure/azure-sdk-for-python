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


class ServicePrincipalBase(Model):
    """Active Directory service principal common properties shared among GET, POST
    and PATCH.

    :param account_enabled: whether or not the service principal account is
     enabled
    :type account_enabled: str
    :param app_role_assignment_required: Specifies whether an
     AppRoleAssignment to a user or group is required before Azure AD will
     issue a user or access token to the application.
    :type app_role_assignment_required: bool
    :param key_credentials: The collection of key credentials associated with
     the service principal.
    :type key_credentials: list[~azure.graphrbac.models.KeyCredential]
    :param password_credentials: The collection of password credentials
     associated with the service principal.
    :type password_credentials:
     list[~azure.graphrbac.models.PasswordCredential]
    :param service_principal_type: the type of the service principal
    :type service_principal_type: str
    :param tags: Optional list of tags that you can apply to your service
     principals. Not nullable.
    :type tags: list[str]
    """

    _attribute_map = {
        'account_enabled': {'key': 'accountEnabled', 'type': 'str'},
        'app_role_assignment_required': {'key': 'appRoleAssignmentRequired', 'type': 'bool'},
        'key_credentials': {'key': 'keyCredentials', 'type': '[KeyCredential]'},
        'password_credentials': {'key': 'passwordCredentials', 'type': '[PasswordCredential]'},
        'service_principal_type': {'key': 'servicePrincipalType', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ServicePrincipalBase, self).__init__(**kwargs)
        self.account_enabled = kwargs.get('account_enabled', None)
        self.app_role_assignment_required = kwargs.get('app_role_assignment_required', None)
        self.key_credentials = kwargs.get('key_credentials', None)
        self.password_credentials = kwargs.get('password_credentials', None)
        self.service_principal_type = kwargs.get('service_principal_type', None)
        self.tags = kwargs.get('tags', None)
