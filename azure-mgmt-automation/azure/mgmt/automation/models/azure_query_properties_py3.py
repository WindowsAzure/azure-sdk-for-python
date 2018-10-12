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


class AzureQueryProperties(Model):
    """Azure query specific to the group of machines for update configuration.

    :param scope: List of Subscription or Resource Group ARM Id.
    :type scope: list[str]
    :param location: list of locations for the VM filter .
    :type location: list[str]
    :param tag_settings: tag filter information of the Vm.
    :type tag_settings: ~azure.mgmt.automation.models.TagSettingsProperties
    """

    _attribute_map = {
        'scope': {'key': 'scope', 'type': '[str]'},
        'location': {'key': 'location', 'type': '[str]'},
        'tag_settings': {'key': 'tagSettings', 'type': 'TagSettingsProperties'},
    }

    def __init__(self, *, scope=None, location=None, tag_settings=None, **kwargs) -> None:
        super(AzureQueryProperties, self).__init__(**kwargs)
        self.scope = scope
        self.location = location
        self.tag_settings = tag_settings
