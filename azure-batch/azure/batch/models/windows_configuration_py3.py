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


class WindowsConfiguration(Model):
    """Windows operating system settings to apply to the virtual machine.

    :param enable_automatic_updates: Whether automatic updates are enabled on
     the virtual machine. If omitted, the default value is true.
    :type enable_automatic_updates: bool
    """

    _attribute_map = {
        'enable_automatic_updates': {'key': 'enableAutomaticUpdates', 'type': 'bool'},
    }

    def __init__(self, *, enable_automatic_updates: bool=None, **kwargs) -> None:
        super(WindowsConfiguration, self).__init__(**kwargs)
        self.enable_automatic_updates = enable_automatic_updates
