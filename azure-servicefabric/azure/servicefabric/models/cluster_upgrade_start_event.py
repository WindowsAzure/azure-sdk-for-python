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

from .cluster_event import ClusterEvent


class ClusterUpgradeStartEvent(ClusterEvent):
    """Cluster Upgrade Start event.

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
    :param current_cluster_version: Required. Current Cluster version.
    :type current_cluster_version: str
    :param target_cluster_version: Required. Target Cluster version.
    :type target_cluster_version: str
    :param upgrade_type: Required. Type of upgrade.
    :type upgrade_type: str
    :param rolling_upgrade_mode: Required. Mode of upgrade.
    :type rolling_upgrade_mode: str
    :param failure_action: Required. Action if failed.
    :type failure_action: str
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'current_cluster_version': {'required': True},
        'target_cluster_version': {'required': True},
        'upgrade_type': {'required': True},
        'rolling_upgrade_mode': {'required': True},
        'failure_action': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'current_cluster_version': {'key': 'CurrentClusterVersion', 'type': 'str'},
        'target_cluster_version': {'key': 'TargetClusterVersion', 'type': 'str'},
        'upgrade_type': {'key': 'UpgradeType', 'type': 'str'},
        'rolling_upgrade_mode': {'key': 'RollingUpgradeMode', 'type': 'str'},
        'failure_action': {'key': 'FailureAction', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ClusterUpgradeStartEvent, self).__init__(**kwargs)
        self.current_cluster_version = kwargs.get('current_cluster_version', None)
        self.target_cluster_version = kwargs.get('target_cluster_version', None)
        self.upgrade_type = kwargs.get('upgrade_type', None)
        self.rolling_upgrade_mode = kwargs.get('rolling_upgrade_mode', None)
        self.failure_action = kwargs.get('failure_action', None)
        self.kind = 'ClusterUpgradeStart'
