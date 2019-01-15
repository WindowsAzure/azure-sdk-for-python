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

from .service_properties import ServiceProperties


class StatefulServiceProperties(ServiceProperties):
    """The properties of a stateful service resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param placement_constraints: The placement constraints as a string.
     Placement constraints are boolean expressions on node properties and allow
     for restricting a service to particular nodes based on the service
     requirements. For example, to place a service on nodes where NodeType is
     blue specify the following: "NodeColor == blue)".
    :type placement_constraints: str
    :param correlation_scheme:
    :type correlation_scheme:
     list[~azure.mgmt.servicefabric.models.ServiceCorrelationDescription]
    :param service_load_metrics:
    :type service_load_metrics:
     list[~azure.mgmt.servicefabric.models.ServiceLoadMetricDescription]
    :param service_placement_policies:
    :type service_placement_policies:
     list[~azure.mgmt.servicefabric.models.ServicePlacementPolicyDescription]
    :param default_move_cost: Possible values include: 'Zero', 'Low',
     'Medium', 'High'
    :type default_move_cost: str or ~azure.mgmt.servicefabric.models.enum
    :ivar provisioning_state: The current deployment or provisioning state,
     which only appears in the response
    :vartype provisioning_state: str
    :param service_type_name: The name of the service type
    :type service_type_name: str
    :param partition_description:
    :type partition_description:
     ~azure.mgmt.servicefabric.models.PartitionSchemeDescription
    :param service_kind: Required. Constant filled by server.
    :type service_kind: str
    :param has_persisted_state: A flag indicating whether this is a persistent
     service which stores states on the local disk. If it is then the value of
     this property is true, if not it is false.
    :type has_persisted_state: bool
    :param target_replica_set_size: The target replica set size as a number.
    :type target_replica_set_size: int
    :param min_replica_set_size: The minimum replica set size as a number.
    :type min_replica_set_size: int
    :param replica_restart_wait_duration: The duration between when a replica
     goes down and when a new replica is created, represented in ISO 8601
     format (hh:mm:ss.s).
    :type replica_restart_wait_duration: datetime
    :param quorum_loss_wait_duration: The maximum duration for which a
     partition is allowed to be in a state of quorum loss, represented in ISO
     8601 format (hh:mm:ss.s).
    :type quorum_loss_wait_duration: datetime
    :param stand_by_replica_keep_duration: The definition on how long StandBy
     replicas should be maintained before being removed, represented in ISO
     8601 format (hh:mm:ss.s).
    :type stand_by_replica_keep_duration: datetime
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'service_kind': {'required': True},
        'target_replica_set_size': {'minimum': 1},
        'min_replica_set_size': {'minimum': 1},
    }

    _attribute_map = {
        'placement_constraints': {'key': 'placementConstraints', 'type': 'str'},
        'correlation_scheme': {'key': 'correlationScheme', 'type': '[ServiceCorrelationDescription]'},
        'service_load_metrics': {'key': 'serviceLoadMetrics', 'type': '[ServiceLoadMetricDescription]'},
        'service_placement_policies': {'key': 'servicePlacementPolicies', 'type': '[ServicePlacementPolicyDescription]'},
        'default_move_cost': {'key': 'defaultMoveCost', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'service_type_name': {'key': 'serviceTypeName', 'type': 'str'},
        'partition_description': {'key': 'partitionDescription', 'type': 'PartitionSchemeDescription'},
        'service_kind': {'key': 'serviceKind', 'type': 'str'},
        'has_persisted_state': {'key': 'hasPersistedState', 'type': 'bool'},
        'target_replica_set_size': {'key': 'targetReplicaSetSize', 'type': 'int'},
        'min_replica_set_size': {'key': 'minReplicaSetSize', 'type': 'int'},
        'replica_restart_wait_duration': {'key': 'replicaRestartWaitDuration', 'type': 'iso-8601'},
        'quorum_loss_wait_duration': {'key': 'quorumLossWaitDuration', 'type': 'iso-8601'},
        'stand_by_replica_keep_duration': {'key': 'standByReplicaKeepDuration', 'type': 'iso-8601'},
    }

    def __init__(self, **kwargs):
        super(StatefulServiceProperties, self).__init__(**kwargs)
        self.has_persisted_state = kwargs.get('has_persisted_state', None)
        self.target_replica_set_size = kwargs.get('target_replica_set_size', None)
        self.min_replica_set_size = kwargs.get('min_replica_set_size', None)
        self.replica_restart_wait_duration = kwargs.get('replica_restart_wait_duration', None)
        self.quorum_loss_wait_duration = kwargs.get('quorum_loss_wait_duration', None)
        self.stand_by_replica_keep_duration = kwargs.get('stand_by_replica_keep_duration', None)
        self.service_kind = 'Stateful'
