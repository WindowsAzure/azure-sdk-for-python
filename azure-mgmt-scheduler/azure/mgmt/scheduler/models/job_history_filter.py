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


class JobHistoryFilter(Model):
    """JobHistoryFilter.

    :param status: Gets or sets the job execution status. Possible values
     include: 'Completed', 'Failed', 'Postponed'
    :type status: str or ~azure.mgmt.scheduler.models.JobExecutionStatus
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'JobExecutionStatus'},
    }

    def __init__(self, **kwargs):
        super(JobHistoryFilter, self).__init__(**kwargs)
        self.status = kwargs.get('status', None)
