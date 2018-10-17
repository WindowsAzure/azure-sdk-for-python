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


class ServicePrincipalCreateParameters(Model):
    """Request parameters for creating a new service principal.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param account_enabled: Whether the account is enabled
    :type account_enabled: bool
    :param app_id: Required. application Id
    :type app_id: str
    :param app_role_assignment_required: Specifies whether an
     AppRoleAssignment to a user or group is required before Azure AD will
     issue a user or access token to the application.
    :type app_role_assignment_required: bool
    :param display_name: The display name for the service principal.
    :type display_name: str
    :param error_url:
    :type error_url: str
    :param homepage: The URL to the homepage of the associated application.
    :type homepage: str
    :param key_credentials: A collection of KeyCredential objects.
    :type key_credentials: list[~azure.graphrbac.models.KeyCredential]
    :param password_credentials: A collection of PasswordCredential objects
    :type password_credentials:
     list[~azure.graphrbac.models.PasswordCredential]
    :param publisher_name: The display name of the tenant in which the
     associated application is specified.
    :type publisher_name: str
    :param reply_urls: A collection of reply URLs for the service principal.
    :type reply_urls: list[str]
    :param saml_metadata_url:
    :type saml_metadata_url: str
    :param service_principal_names: A collection of service principal names.
    :type service_principal_names: list[str]
    :param tags:
    :type tags: list[str]
    """

    _validation = {
        'app_id': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'account_enabled': {'key': 'accountEnabled', 'type': 'bool'},
        'app_id': {'key': 'appId', 'type': 'str'},
        'app_role_assignment_required': {'key': 'appRoleAssignmentRequired', 'type': 'bool'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'error_url': {'key': 'errorUrl', 'type': 'str'},
        'homepage': {'key': 'homepage', 'type': 'str'},
        'key_credentials': {'key': 'keyCredentials', 'type': '[KeyCredential]'},
        'password_credentials': {'key': 'passwordCredentials', 'type': '[PasswordCredential]'},
        'publisher_name': {'key': 'publisherName', 'type': 'str'},
        'reply_urls': {'key': 'replyUrls', 'type': '[str]'},
        'saml_metadata_url': {'key': 'samlMetadataUrl', 'type': 'str'},
        'service_principal_names': {'key': 'servicePrincipalNames', 'type': '[str]'},
        'tags': {'key': 'tags', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ServicePrincipalCreateParameters, self).__init__(**kwargs)
        self.additional_properties = kwargs.get('additional_properties', None)
        self.account_enabled = kwargs.get('account_enabled', None)
        self.app_id = kwargs.get('app_id', None)
        self.app_role_assignment_required = kwargs.get('app_role_assignment_required', None)
        self.display_name = kwargs.get('display_name', None)
        self.error_url = kwargs.get('error_url', None)
        self.homepage = kwargs.get('homepage', None)
        self.key_credentials = kwargs.get('key_credentials', None)
        self.password_credentials = kwargs.get('password_credentials', None)
        self.publisher_name = kwargs.get('publisher_name', None)
        self.reply_urls = kwargs.get('reply_urls', None)
        self.saml_metadata_url = kwargs.get('saml_metadata_url', None)
        self.service_principal_names = kwargs.get('service_principal_names', None)
        self.tags = kwargs.get('tags', None)
