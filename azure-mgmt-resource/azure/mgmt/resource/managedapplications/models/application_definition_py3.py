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

from .generic_resource import GenericResource


class ApplicationDefinition(GenericResource):
    """Information about managed application definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param managed_by: ID of the resource that manages this resource.
    :type managed_by: str
    :param sku: The SKU of the resource.
    :type sku: ~azure.mgmt.resource.managedapplications.models.Sku
    :param identity: The identity of the resource.
    :type identity: ~azure.mgmt.resource.managedapplications.models.Identity
    :param lock_level: Required. The managed application lock level. Possible
     values include: 'CanNotDelete', 'ReadOnly', 'None'
    :type lock_level: str or
     ~azure.mgmt.resource.managedapplications.models.ApplicationLockLevel
    :param display_name: The managed application definition display name.
    :type display_name: str
    :param is_enabled: A value indicating whether the package is enabled or
     not.
    :type is_enabled: str
    :param authorizations: Required. The managed application provider
     authorizations.
    :type authorizations:
     list[~azure.mgmt.resource.managedapplications.models.ApplicationProviderAuthorization]
    :param artifacts: The collection of managed application artifacts. The
     portal will use the files specified as artifacts to construct the user
     experience of creating a managed application from a managed application
     definition.
    :type artifacts:
     list[~azure.mgmt.resource.managedapplications.models.ApplicationArtifact]
    :param description: The managed application definition description.
    :type description: str
    :param package_file_uri: The managed application definition package file
     Uri. Use this element
    :type package_file_uri: str
    :param main_template: The inline main template json which has resources to
     be provisioned. It can be a JObject or well-formed JSON string.
    :type main_template: object
    :param create_ui_definition: The createUiDefinition json for the backing
     template with Microsoft.Solutions/applications resource. It can be a
     JObject or well-formed JSON string.
    :type create_ui_definition: object
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'lock_level': {'required': True},
        'authorizations': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'managed_by': {'key': 'managedBy', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'identity': {'key': 'identity', 'type': 'Identity'},
        'lock_level': {'key': 'properties.lockLevel', 'type': 'ApplicationLockLevel'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'is_enabled': {'key': 'properties.isEnabled', 'type': 'str'},
        'authorizations': {'key': 'properties.authorizations', 'type': '[ApplicationProviderAuthorization]'},
        'artifacts': {'key': 'properties.artifacts', 'type': '[ApplicationArtifact]'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'package_file_uri': {'key': 'properties.packageFileUri', 'type': 'str'},
        'main_template': {'key': 'properties.mainTemplate', 'type': 'object'},
        'create_ui_definition': {'key': 'properties.createUiDefinition', 'type': 'object'},
    }

    def __init__(self, *, lock_level, authorizations, location: str=None, tags=None, managed_by: str=None, sku=None, identity=None, display_name: str=None, is_enabled: str=None, artifacts=None, description: str=None, package_file_uri: str=None, main_template=None, create_ui_definition=None, **kwargs) -> None:
        super(ApplicationDefinition, self).__init__(location=location, tags=tags, managed_by=managed_by, sku=sku, identity=identity, **kwargs)
        self.lock_level = lock_level
        self.display_name = display_name
        self.is_enabled = is_enabled
        self.authorizations = authorizations
        self.artifacts = artifacts
        self.description = description
        self.package_file_uri = package_file_uri
        self.main_template = main_template
        self.create_ui_definition = create_ui_definition
