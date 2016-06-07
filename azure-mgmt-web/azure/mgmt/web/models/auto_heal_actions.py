# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class AutoHealActions(Model):
    """
    AutoHealActions - Describes the actions which can be
    taken by the auto-heal module when a rule is triggered.

    :param action_type: ActionType - predefined action to be taken. Possible
     values include: 'Recycle', 'LogEvent', 'CustomAction'
    :type action_type: str or :class:`AutoHealActionType
     <azure.mgmt.web.models.AutoHealActionType>`
    :param custom_action: CustomAction - custom action to be taken
    :type custom_action: :class:`AutoHealCustomAction
     <azure.mgmt.web.models.AutoHealCustomAction>`
    :param min_process_execution_time: MinProcessExecutionTime - minimum time
     the process must execute
     before taking the action
    :type min_process_execution_time: str
    """ 

    _validation = {
        'action_type': {'required': True},
    }

    _attribute_map = {
        'action_type': {'key': 'actionType', 'type': 'AutoHealActionType'},
        'custom_action': {'key': 'customAction', 'type': 'AutoHealCustomAction'},
        'min_process_execution_time': {'key': 'minProcessExecutionTime', 'type': 'str'},
    }

    def __init__(self, action_type, custom_action=None, min_process_execution_time=None):
        self.action_type = action_type
        self.custom_action = custom_action
        self.min_process_execution_time = min_process_execution_time
