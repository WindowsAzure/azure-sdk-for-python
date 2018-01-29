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


class HealthEvaluation(Model):
    """Represents a health evaluation which describes the data and the algorithm
    used by health manager to evaluate the health of an entity.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: ApplicationHealthEvaluation, ApplicationsHealthEvaluation,
    ApplicationTypeApplicationsHealthEvaluation,
    DeltaNodesCheckHealthEvaluation, DeployedApplicationHealthEvaluation,
    DeployedApplicationsHealthEvaluation,
    DeployedServicePackageHealthEvaluation,
    DeployedServicePackagesHealthEvaluation, EventHealthEvaluation,
    NodeHealthEvaluation, NodesHealthEvaluation, PartitionHealthEvaluation,
    PartitionsHealthEvaluation, ReplicaHealthEvaluation,
    ReplicasHealthEvaluation, ServiceHealthEvaluation,
    ServicesHealthEvaluation, SystemApplicationHealthEvaluation,
    UpgradeDomainDeltaNodesCheckHealthEvaluation,
    UpgradeDomainNodesHealthEvaluation

    :param aggregated_health_state: Possible values include: 'Invalid', 'Ok',
     'Warning', 'Error', 'Unknown'
    :type aggregated_health_state: str or ~azure.servicefabric.models.enum
    :param description: Description of the health evaluation, which represents
     a summary of the evaluation process.
    :type description: str
    :param kind: Constant filled by server.
    :type kind: str
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'description': {'key': 'Description', 'type': 'str'},
        'kind': {'key': 'Kind', 'type': 'str'},
    }

    _subtype_map = {
        'kind': {'Application': 'ApplicationHealthEvaluation', 'Applications': 'ApplicationsHealthEvaluation', 'ApplicationTypeApplications': 'ApplicationTypeApplicationsHealthEvaluation', 'DeltaNodesCheck': 'DeltaNodesCheckHealthEvaluation', 'DeployedApplication': 'DeployedApplicationHealthEvaluation', 'DeployedApplications': 'DeployedApplicationsHealthEvaluation', 'DeployedServicePackage': 'DeployedServicePackageHealthEvaluation', 'DeployedServicePackages': 'DeployedServicePackagesHealthEvaluation', 'Event': 'EventHealthEvaluation', 'Node': 'NodeHealthEvaluation', 'Nodes': 'NodesHealthEvaluation', 'Partition': 'PartitionHealthEvaluation', 'Partitions': 'PartitionsHealthEvaluation', 'Replica': 'ReplicaHealthEvaluation', 'Replicas': 'ReplicasHealthEvaluation', 'Service': 'ServiceHealthEvaluation', 'Services': 'ServicesHealthEvaluation', 'SystemApplication': 'SystemApplicationHealthEvaluation', 'UpgradeDomainDeltaNodesCheck': 'UpgradeDomainDeltaNodesCheckHealthEvaluation', 'UpgradeDomainNodes': 'UpgradeDomainNodesHealthEvaluation'}
    }

    def __init__(self, aggregated_health_state=None, description=None):
        super(HealthEvaluation, self).__init__()
        self.aggregated_health_state = aggregated_health_state
        self.description = description
        self.kind = None
