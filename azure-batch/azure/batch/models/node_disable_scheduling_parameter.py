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


class NodeDisableSchedulingParameter(Model):
    """
    Parameters for a ComputeNodeOperations.DisableScheduling request.

    :param node_disable_scheduling_option: What to do with currently running
     tasks when disable task scheduling on the compute node. The default
     value is requeue. Possible values include: 'requeue', 'terminate',
     'taskcompletion'
    :type node_disable_scheduling_option: str or
     :class:`DisableComputeNodeSchedulingOption
     <azure.batch.models.DisableComputeNodeSchedulingOption>`
    """ 

    _attribute_map = {
        'node_disable_scheduling_option': {'key': 'nodeDisableSchedulingOption', 'type': 'DisableComputeNodeSchedulingOption'},
    }

    def __init__(self, node_disable_scheduling_option=None):
        self.node_disable_scheduling_option = node_disable_scheduling_option
