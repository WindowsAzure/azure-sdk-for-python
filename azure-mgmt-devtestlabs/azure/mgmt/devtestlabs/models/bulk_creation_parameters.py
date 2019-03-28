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


class BulkCreationParameters(Model):
    """Parameters for creating multiple virtual machines as a single action.

    :param instance_count: The number of virtual machine instances to create.
    :type instance_count: int
    """

    _attribute_map = {
        'instance_count': {'key': 'instanceCount', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(BulkCreationParameters, self).__init__(**kwargs)
        self.instance_count = kwargs.get('instance_count', None)
