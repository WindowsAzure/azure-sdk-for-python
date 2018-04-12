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

from .health_evaluation import HealthEvaluation


class UpgradeDomainNodesHealthEvaluation(HealthEvaluation):
    """Represents health evaluation for cluster nodes in an upgrade domain,
    containing health evaluations for each unhealthy node that impacted current
    aggregated health state. Can be returned when evaluating cluster health
    during cluster upgrade and the aggregated health state is either Error or
    Warning.

    All required parameters must be populated in order to send to Azure.

    :param aggregated_health_state: The health state of a Service Fabric
     entity such as Cluster, Node, Application, Service, Partition, Replica
     etc. Possible values include: 'Invalid', 'Ok', 'Warning', 'Error',
     'Unknown'
    :type aggregated_health_state: str or
     ~azure.servicefabric.models.HealthState
    :param description: Description of the health evaluation, which represents
     a summary of the evaluation process.
    :type description: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param upgrade_domain_name: Name of the upgrade domain where nodes health
     is currently evaluated.
    :type upgrade_domain_name: str
    :param max_percent_unhealthy_nodes: Maximum allowed percentage of
     unhealthy nodes from the ClusterHealthPolicy.
    :type max_percent_unhealthy_nodes: int
    :param total_count: Total number of nodes in the current upgrade domain.
    :type total_count: long
    :param unhealthy_evaluations: List of unhealthy evaluations that led to
     the aggregated health state. Includes all the unhealthy
     NodeHealthEvaluation that impacted the aggregated health.
    :type unhealthy_evaluations:
     list[~azure.servicefabric.models.HealthEvaluationWrapper]
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'description': {'key': 'Description', 'type': 'str'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'upgrade_domain_name': {'key': 'UpgradeDomainName', 'type': 'str'},
        'max_percent_unhealthy_nodes': {'key': 'MaxPercentUnhealthyNodes', 'type': 'int'},
        'total_count': {'key': 'TotalCount', 'type': 'long'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': '[HealthEvaluationWrapper]'},
    }

    def __init__(self, *, aggregated_health_state=None, description: str=None, upgrade_domain_name: str=None, max_percent_unhealthy_nodes: int=None, total_count: int=None, unhealthy_evaluations=None, **kwargs) -> None:
        super(UpgradeDomainNodesHealthEvaluation, self).__init__(aggregated_health_state=aggregated_health_state, description=description, **kwargs)
        self.upgrade_domain_name = upgrade_domain_name
        self.max_percent_unhealthy_nodes = max_percent_unhealthy_nodes
        self.total_count = total_count
        self.unhealthy_evaluations = unhealthy_evaluations
        self.kind = 'UpgradeDomainNodes'
