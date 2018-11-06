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

from .directory_object import DirectoryObject


class Application(DirectoryObject):
    """Active Directory application information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :ivar object_id: The object ID.
    :vartype object_id: str
    :ivar deletion_timestamp: The time at which the directory object was
     deleted.
    :vartype deletion_timestamp: datetime
    :param object_type: Required. Constant filled by server.
    :type object_type: str
    :param app_id: The application ID.
    :type app_id: str
    :param app_roles: The collection of application roles that an application
     may declare. These roles can be assigned to users, groups or service
     principals.
    :type app_roles: list[~azure.graphrbac.models.AppRole]
    :param app_permissions: The application permissions.
    :type app_permissions: list[str]
    :param available_to_other_tenants: Whether the application is be available
     to other tenants.
    :type available_to_other_tenants: bool
    :param display_name: The display name of the application.
    :type display_name: str
    :param identifier_uris: A collection of URIs for the application.
    :type identifier_uris: list[str]
    :param reply_urls: A collection of reply URLs for the application.
    :type reply_urls: list[str]
    :param homepage: The home page of the application.
    :type homepage: str
    :param oauth2_allow_implicit_flow: Whether to allow implicit grant flow
     for OAuth2
    :type oauth2_allow_implicit_flow: bool
    :param required_resource_access: Specifies resources that this application
     requires access to and the set of OAuth permission scopes and application
     roles that it needs under each of those resources. This pre-configuration
     of required resource access drives the consent experience.
    :type required_resource_access:
     list[~azure.graphrbac.models.RequiredResourceAccess]
    """

    _validation = {
        'object_id': {'readonly': True},
        'deletion_timestamp': {'readonly': True},
        'object_type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'object_id': {'key': 'objectId', 'type': 'str'},
        'deletion_timestamp': {'key': 'deletionTimestamp', 'type': 'iso-8601'},
        'object_type': {'key': 'objectType', 'type': 'str'},
        'app_id': {'key': 'appId', 'type': 'str'},
        'app_roles': {'key': 'appRoles', 'type': '[AppRole]'},
        'app_permissions': {'key': 'appPermissions', 'type': '[str]'},
        'available_to_other_tenants': {'key': 'availableToOtherTenants', 'type': 'bool'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'identifier_uris': {'key': 'identifierUris', 'type': '[str]'},
        'reply_urls': {'key': 'replyUrls', 'type': '[str]'},
        'homepage': {'key': 'homepage', 'type': 'str'},
        'oauth2_allow_implicit_flow': {'key': 'oauth2AllowImplicitFlow', 'type': 'bool'},
        'required_resource_access': {'key': 'requiredResourceAccess', 'type': '[RequiredResourceAccess]'},
    }

    def __init__(self, **kwargs):
        super(Application, self).__init__(**kwargs)
        self.app_id = kwargs.get('app_id', None)
        self.app_roles = kwargs.get('app_roles', None)
        self.app_permissions = kwargs.get('app_permissions', None)
        self.available_to_other_tenants = kwargs.get('available_to_other_tenants', None)
        self.display_name = kwargs.get('display_name', None)
        self.identifier_uris = kwargs.get('identifier_uris', None)
        self.reply_urls = kwargs.get('reply_urls', None)
        self.homepage = kwargs.get('homepage', None)
        self.oauth2_allow_implicit_flow = kwargs.get('oauth2_allow_implicit_flow', None)
        self.required_resource_access = kwargs.get('required_resource_access', None)
        self.object_type = 'Application'
