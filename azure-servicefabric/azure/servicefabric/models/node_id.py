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


class NodeId(Model):
    """An internal ID used by Service Fabric to uniquely identify a node. Node Id
    is deterministically generated from node name.

    :param id: Value of the node Id. This is a 128 bit integer.
    :type id: str
    """

    _attribute_map = {
        'id': {'key': 'Id', 'type': 'str'},
    }

    def __init__(self, id=None):
        super(NodeId, self).__init__()
        self.id = id
