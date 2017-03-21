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


class NodeReimageParameter(Model):
    """Options for reimaging a compute node.

    :param node_reimage_option: When to reimage the compute node and what to
     do with currently running tasks. The default value is requeue. Possible
     values include: 'requeue', 'terminate', 'taskCompletion', 'retainedData'
    :type node_reimage_option: str or :class:`ComputeNodeReimageOption
     <azure.batch.models.ComputeNodeReimageOption>`
    """

    _attribute_map = {
        'node_reimage_option': {'key': 'nodeReimageOption', 'type': 'ComputeNodeReimageOption'},
    }

    def __init__(self, node_reimage_option=None):
        self.node_reimage_option = node_reimage_option
