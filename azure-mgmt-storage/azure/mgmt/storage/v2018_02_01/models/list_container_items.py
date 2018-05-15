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


class ListContainerItems(Model):
    """The list of blob containers.

    :param value: The list of blob containers.
    :type value:
     list[~azure.mgmt.storage.v2018_02_01.models.ListContainerItem]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ListContainerItem]'},
    }

    def __init__(self, **kwargs):
        super(ListContainerItems, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
