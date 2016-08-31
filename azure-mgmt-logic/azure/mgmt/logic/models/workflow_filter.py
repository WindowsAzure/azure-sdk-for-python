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
    """WorkflowFilter.

    :param state: Gets or sets the state of workflows. Possible values
     include: 'NotSpecified', 'Enabled', 'Disabled', 'Deleted', 'Suspended'
    :type state: str or :class:`WorkflowState
     <azure.mgmt.logic.models.WorkflowState>`
    """ 

    _attribute_map = {
        'state': {'key': 'state', 'type': 'WorkflowState'},
    }

    def __init__(self, state=None):
        self.state = state
