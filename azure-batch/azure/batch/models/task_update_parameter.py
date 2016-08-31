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


class TaskUpdateParameter(Model):
    """Parameters for a CloudTaskOperations.Update request.

    :param constraints: Constraints that apply to this task. If omitted, the
     task is given the default constraints.
    :type constraints: :class:`TaskConstraints
     <azure.batch.models.TaskConstraints>`
    """ 

    _attribute_map = {
        'constraints': {'key': 'constraints', 'type': 'TaskConstraints'},
    }

    def __init__(self, constraints=None):
        self.constraints = constraints
