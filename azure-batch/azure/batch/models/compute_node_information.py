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


class ComputeNodeInformation(Model):
    """Information about the compute node on which a task ran.

    :param affinity_id: An identifier for the compute node on which the task
     ran, which can be passed when adding a task to request that the task be
     scheduled close to this compute node.
    :type affinity_id: str
    :param node_url: The URL of the node on which the task ran. .
    :type node_url: str
    :param pool_id: The ID of the pool on which the task ran.
    :type pool_id: str
    :param node_id: The ID of the node on which the task ran.
    :type node_id: str
    :param task_root_directory: The root directory of the task on the compute
     node.
    :type task_root_directory: str
    :param task_root_directory_url: The URL to the root directory of the task
     on the compute node.
    :type task_root_directory_url: str
    """

    _attribute_map = {
        'affinity_id': {'key': 'affinityId', 'type': 'str'},
        'node_url': {'key': 'nodeUrl', 'type': 'str'},
        'pool_id': {'key': 'poolId', 'type': 'str'},
        'node_id': {'key': 'nodeId', 'type': 'str'},
        'task_root_directory': {'key': 'taskRootDirectory', 'type': 'str'},
        'task_root_directory_url': {'key': 'taskRootDirectoryUrl', 'type': 'str'},
    }

    def __init__(self, affinity_id=None, node_url=None, pool_id=None, node_id=None, task_root_directory=None, task_root_directory_url=None):
        self.affinity_id = affinity_id
        self.node_url = node_url
        self.pool_id = pool_id
        self.node_id = node_id
        self.task_root_directory = task_root_directory
        self.task_root_directory_url = task_root_directory_url
