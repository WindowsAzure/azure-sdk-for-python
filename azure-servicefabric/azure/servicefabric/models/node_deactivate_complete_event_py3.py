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

from .node_event_py3 import NodeEvent


class NodeDeactivateCompleteEvent(NodeEvent):
    """Node Deactivate Complete event.

    All required parameters must be populated in order to send to Azure.

    :param event_instance_id: Required. The identifier for the FabricEvent
     instance.
    :type event_instance_id: str
    :param time_stamp: Required. The time event was logged.
    :type time_stamp: datetime
    :param has_correlated_events: Shows there is existing related events
     available.
    :type has_correlated_events: bool
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param node_name: Required. The name of a Service Fabric node.
    :type node_name: str
    :param node_instance: Required. Id of Node instance.
    :type node_instance: long
    :param effective_deactivate_intent: Required. Describes deactivate intent.
    :type effective_deactivate_intent: str
    :param batch_ids_with_deactivate_intent: Required. Batch Ids.
    :type batch_ids_with_deactivate_intent: str
    :param start_time: Required. Start time.
    :type start_time: datetime
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'node_name': {'required': True},
        'node_instance': {'required': True},
        'effective_deactivate_intent': {'required': True},
        'batch_ids_with_deactivate_intent': {'required': True},
        'start_time': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'node_name': {'key': 'NodeName', 'type': 'str'},
        'node_instance': {'key': 'NodeInstance', 'type': 'long'},
        'effective_deactivate_intent': {'key': 'EffectiveDeactivateIntent', 'type': 'str'},
        'batch_ids_with_deactivate_intent': {'key': 'BatchIdsWithDeactivateIntent', 'type': 'str'},
        'start_time': {'key': 'StartTime', 'type': 'iso-8601'},
    }

    def __init__(self, *, event_instance_id: str, time_stamp, node_name: str, node_instance: int, effective_deactivate_intent: str, batch_ids_with_deactivate_intent: str, start_time, has_correlated_events: bool=None, **kwargs) -> None:
        super(NodeDeactivateCompleteEvent, self).__init__(event_instance_id=event_instance_id, time_stamp=time_stamp, has_correlated_events=has_correlated_events, node_name=node_name, **kwargs)
        self.node_instance = node_instance
        self.effective_deactivate_intent = effective_deactivate_intent
        self.batch_ids_with_deactivate_intent = batch_ids_with_deactivate_intent
        self.start_time = start_time
        self.kind = 'NodeDeactivateComplete'
