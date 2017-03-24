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


class AffinityInformation(Model):
    """A locality hint that can be used by the Batch service to select a compute
    node on which to start a task.

    :param affinity_id: An opaque string representing the location of a
     compute node or a task that has run previously. You can pass the
     affinityId of a compute node or task to indicate that this task needs to
     be placed close to the node or task.
    :type affinity_id: str
    """

    _validation = {
        'affinity_id': {'required': True},
    }

    _attribute_map = {
        'affinity_id': {'key': 'affinityId', 'type': 'str'},
    }

    def __init__(self, affinity_id):
        self.affinity_id = affinity_id
