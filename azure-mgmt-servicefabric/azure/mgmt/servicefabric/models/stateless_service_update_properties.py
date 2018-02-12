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

from .service_update_properties import ServiceUpdateProperties


class StatelessServiceUpdateProperties(ServiceUpdateProperties):
    """The properties of a stateless service resource for patch operations.

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
    :param service_kind: Constant filled by server.
    :type service_kind: str
    :param instance_count: The instance count.
    :type instance_count: int
    """

    _validation = {
        'service_kind': {'required': True},
        'instance_count': {'minimum': -1},
    }

    _attribute_map = {
        'placement_constraints': {'key': 'placementConstraints', 'type': 'str'},
        'correlation_scheme': {'key': 'correlationScheme', 'type': '[ServiceCorrelationDescription]'},
        'service_load_metrics': {'key': 'serviceLoadMetrics', 'type': '[ServiceLoadMetricDescription]'},
        'service_placement_policies': {'key': 'servicePlacementPolicies', 'type': '[ServicePlacementPolicyDescription]'},
        'default_move_cost': {'key': 'defaultMoveCost', 'type': 'str'},
        'service_kind': {'key': 'serviceKind', 'type': 'str'},
        'instance_count': {'key': 'instanceCount', 'type': 'int'},
    }

    def __init__(self, placement_constraints=None, correlation_scheme=None, service_load_metrics=None, service_placement_policies=None, default_move_cost=None, instance_count=None):
        super(StatelessServiceUpdateProperties, self).__init__(placement_constraints=placement_constraints, correlation_scheme=correlation_scheme, service_load_metrics=service_load_metrics, service_placement_policies=service_placement_policies, default_move_cost=default_move_cost)
        self.instance_count = instance_count
        self.service_kind = 'Stateless'
