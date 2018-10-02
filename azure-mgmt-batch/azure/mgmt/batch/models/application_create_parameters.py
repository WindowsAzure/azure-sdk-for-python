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


class ApplicationCreateParameters(Model):
    """Parameters for adding an Application.

    :param allow_updates: A value indicating whether packages within the
     application may be overwritten using the same version string.
    :type allow_updates: bool
    :param display_name: The display name for the application.
    :type display_name: str
    """

    _attribute_map = {
        'allow_updates': {'key': 'allowUpdates', 'type': 'bool'},
        'display_name': {'key': 'displayName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ApplicationCreateParameters, self).__init__(**kwargs)
        self.allow_updates = kwargs.get('allow_updates', None)
        self.display_name = kwargs.get('display_name', None)
