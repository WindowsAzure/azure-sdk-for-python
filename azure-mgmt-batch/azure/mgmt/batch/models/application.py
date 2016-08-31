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


class Application(Model):
    """Contains information about an application in a Batch account.

    :param id: A string that uniquely identifies the application within the
     account.
    :type id: str
    :param display_name: The display name for the application.
    :type display_name: str
    :param packages: The list of packages under this application.
    :type packages: list of :class:`ApplicationPackage
     <azure.mgmt.batch.models.ApplicationPackage>`
    :param allow_updates: A value indicating whether packages within the
     application may be overwritten using the same version string.
    :type allow_updates: bool
    :param default_version: The package to use if a client requests the
     application but does not specify a version.
    :type default_version: str
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'packages': {'key': 'packages', 'type': '[ApplicationPackage]'},
        'allow_updates': {'key': 'allowUpdates', 'type': 'bool'},
        'default_version': {'key': 'defaultVersion', 'type': 'str'},
    }

    def __init__(self, id=None, display_name=None, packages=None, allow_updates=None, default_version=None):
        self.id = id
        self.display_name = display_name
        self.packages = packages
        self.allow_updates = allow_updates
        self.default_version = default_version
