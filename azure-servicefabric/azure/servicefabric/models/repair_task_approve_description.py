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


class RepairTaskApproveDescription(Model):
    """Describes a request for forced approval of a repair task.
    This type supports the Service Fabric platform; it is not meant to be used
    directly from your code.
    .

    :param task_id: The ID of the repair task.
    :type task_id: str
    :param version: The current version number of the repair task. If
     non-zero, then the request will only succeed if this value matches the
     actual current version of the repair task. If zero, then no version check
     is performed.</para>
    :type version: str
    """

    _validation = {
        'task_id': {'required': True},
    }

    _attribute_map = {
        'task_id': {'key': 'TaskId', 'type': 'str'},
        'version': {'key': 'Version', 'type': 'str'},
    }

    def __init__(self, task_id, version=None):
        super(RepairTaskApproveDescription, self).__init__()
        self.task_id = task_id
        self.version = version
