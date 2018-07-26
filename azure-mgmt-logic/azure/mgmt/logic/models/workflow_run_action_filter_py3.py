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


class WorkflowRunActionFilter(Model):
    """The workflow run action filter.

    :param status: The status of workflow run action. Possible values include:
     'NotSpecified', 'Paused', 'Running', 'Waiting', 'Succeeded', 'Skipped',
     'Suspended', 'Cancelled', 'Failed', 'Faulted', 'TimedOut', 'Aborted',
     'Ignored'
    :type status: str or ~azure.mgmt.logic.models.WorkflowStatus
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'WorkflowStatus'},
    }

    def __init__(self, *, status=None, **kwargs) -> None:
        super(WorkflowRunActionFilter, self).__init__(**kwargs)
        self.status = status
