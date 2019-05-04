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


class ResourceSet(Model):
    """Represents a VM and the setting Id it was created for.

    :param vm_resource_id: VM resource Id for the environment
    :type vm_resource_id: str
    :param resource_setting_id: resourceSettingId for the environment
    :type resource_setting_id: str
    """

    _attribute_map = {
        'vm_resource_id': {'key': 'vmResourceId', 'type': 'str'},
        'resource_setting_id': {'key': 'resourceSettingId', 'type': 'str'},
    }

    def __init__(self, *, vm_resource_id: str=None, resource_setting_id: str=None, **kwargs) -> None:
        super(ResourceSet, self).__init__(**kwargs)
        self.vm_resource_id = vm_resource_id
        self.resource_setting_id = resource_setting_id
