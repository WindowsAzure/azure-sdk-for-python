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

from .fabric_event import FabricEvent


class ClusterEvent(FabricEvent):
    """Represents the base for all Cluster Events.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: ClusterNewHealthReportEvent,
    ClusterHealthReportExpiredEvent, ClusterUpgradeCompletedEvent,
    ClusterUpgradeDomainCompletedEvent, ClusterUpgradeRollbackCompletedEvent,
    ClusterUpgradeRollbackStartedEvent, ClusterUpgradeStartedEvent,
    ChaosStoppedEvent, ChaosStartedEvent

    All required parameters must be populated in order to send to Azure.

    :param event_instance_id: Required. The identifier for the FabricEvent
     instance.
    :type event_instance_id: str
    :param category: The category of event.
    :type category: str
    :param time_stamp: Required. The time event was logged.
    :type time_stamp: datetime
    :param has_correlated_events: Shows there is existing related events
     available.
    :type has_correlated_events: bool
    :param kind: Required. Constant filled by server.
    :type kind: str
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'category': {'key': 'Category', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
    }

    _subtype_map = {
        'kind': {'ClusterNewHealthReport': 'ClusterNewHealthReportEvent', 'ClusterHealthReportExpired': 'ClusterHealthReportExpiredEvent', 'ClusterUpgradeCompleted': 'ClusterUpgradeCompletedEvent', 'ClusterUpgradeDomainCompleted': 'ClusterUpgradeDomainCompletedEvent', 'ClusterUpgradeRollbackCompleted': 'ClusterUpgradeRollbackCompletedEvent', 'ClusterUpgradeRollbackStarted': 'ClusterUpgradeRollbackStartedEvent', 'ClusterUpgradeStarted': 'ClusterUpgradeStartedEvent', 'ChaosStopped': 'ChaosStoppedEvent', 'ChaosStarted': 'ChaosStartedEvent'}
    }

    def __init__(self, **kwargs):
        super(ClusterEvent, self).__init__(**kwargs)
        self.kind = 'ClusterEvent'
