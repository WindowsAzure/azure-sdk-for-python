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


class ResourcesMoveInfo(Model):
    """Parameters of move resources.

    :param resources: The IDs of the resources.
    :type resources: list[str]
    :param target_resource_group: The target resource group.
    :type target_resource_group: str
    """

    _attribute_map = {
        'resources': {'key': 'resources', 'type': '[str]'},
        'target_resource_group': {'key': 'targetResourceGroup', 'type': 'str'},
    }

    def __init__(self, *, resources=None, target_resource_group: str=None, **kwargs) -> None:
        super(ResourcesMoveInfo, self).__init__(**kwargs)
        self.resources = resources
        self.target_resource_group = target_resource_group
