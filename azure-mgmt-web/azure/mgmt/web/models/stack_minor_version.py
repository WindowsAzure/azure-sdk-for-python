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


class StackMinorVersion(Model):
    """Application stack minor version.

    :param display_version: Application stack minor version (display only).
    :type display_version: str
    :param runtime_version: Application stack minor version (runtime only).
    :type runtime_version: str
    :param is_default: <code>true</code> if this is the default minor version;
     otherwise, <code>false</code>.
    :type is_default: bool
    """

    _attribute_map = {
        'display_version': {'key': 'displayVersion', 'type': 'str'},
        'runtime_version': {'key': 'runtimeVersion', 'type': 'str'},
        'is_default': {'key': 'isDefault', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(StackMinorVersion, self).__init__(**kwargs)
        self.display_version = kwargs.get('display_version', None)
        self.runtime_version = kwargs.get('runtime_version', None)
        self.is_default = kwargs.get('is_default', None)
