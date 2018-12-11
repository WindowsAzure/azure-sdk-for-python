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


class WorkflowFilter(Model):
    """The workflow filter.

    :param state: The state of workflows. Possible values include:
     'NotSpecified', 'Completed', 'Enabled', 'Disabled', 'Deleted', 'Suspended'
    :type state: str or ~azure.mgmt.logic.models.WorkflowState
    """

    _attribute_map = {
        'state': {'key': 'state', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(WorkflowFilter, self).__init__(**kwargs)
        self.state = kwargs.get('state', None)
