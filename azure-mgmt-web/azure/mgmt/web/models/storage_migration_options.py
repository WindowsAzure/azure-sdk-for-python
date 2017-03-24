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


class StorageMigrationOptions(Resource):
    """Options for app content migration.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :param name: Resource Name.
    :type name: str
    :param kind: Kind of resource.
    :type kind: str
    :param location: Resource Location.
    :type location: str
    :param type: Resource type.
    :type type: str
    :param tags: Resource tags.
    :type tags: dict
    :param azurefiles_connection_string: AzureFiles connection string.
    :type azurefiles_connection_string: str
    :param azurefiles_share: AzureFiles share.
    :type azurefiles_share: str
    :param switch_site_after_migration: <code>true</code>if the app should be
     switched over; otherwise, <code>false</code>. Default value: False .
    :type switch_site_after_migration: bool
    :param block_write_access_to_site: <code>true</code> if the app should be
     read only during copy operation; otherwise, <code>false</code>. Default
     value: False .
    :type block_write_access_to_site: bool
    """

    _validation = {
        'id': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'azurefiles_connection_string': {'key': 'properties.azurefilesConnectionString', 'type': 'str'},
        'azurefiles_share': {'key': 'properties.azurefilesShare', 'type': 'str'},
        'switch_site_after_migration': {'key': 'properties.switchSiteAfterMigration', 'type': 'bool'},
        'block_write_access_to_site': {'key': 'properties.blockWriteAccessToSite', 'type': 'bool'},
    }

    def __init__(self, location, name=None, kind=None, type=None, tags=None, azurefiles_connection_string=None, azurefiles_share=None, switch_site_after_migration=False, block_write_access_to_site=False):
        super(StorageMigrationOptions, self).__init__(name=name, kind=kind, location=location, type=type, tags=tags)
        self.azurefiles_connection_string = azurefiles_connection_string
        self.azurefiles_share = azurefiles_share
        self.switch_site_after_migration = switch_site_after_migration
        self.block_write_access_to_site = block_write_access_to_site
