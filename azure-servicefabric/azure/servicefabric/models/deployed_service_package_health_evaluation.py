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


class DeployedServicePackageHealthEvaluation(HealthEvaluation):
    """Represents health evaluation for a deployed service package, containing
    information about the data and the algorithm used by health store to
    evaluate health. The evaluation is returned only when the aggregated health
    state is either Error or Warning.

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
    :param node_name: The name of a Service Fabric node.
    :type node_name: str
    :param application_name: The name of the application, including the
     'fabric:' URI scheme.
    :type application_name: str
    :param service_manifest_name: The name of the service manifest.
    :type service_manifest_name: str
    :param unhealthy_evaluations: List of unhealthy evaluations that led to
     the current aggregated health state. The type of the unhealthy evaluations
     can be EventHealthEvaluation.
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
        'node_name': {'key': 'NodeName', 'type': 'str'},
        'application_name': {'key': 'ApplicationName', 'type': 'str'},
        'service_manifest_name': {'key': 'ServiceManifestName', 'type': 'str'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': '[HealthEvaluationWrapper]'},
    }

    def __init__(self, **kwargs):
        super(DeployedServicePackageHealthEvaluation, self).__init__(**kwargs)
        self.node_name = kwargs.get('node_name', None)
        self.application_name = kwargs.get('application_name', None)
        self.service_manifest_name = kwargs.get('service_manifest_name', None)
        self.unhealthy_evaluations = kwargs.get('unhealthy_evaluations', None)
        self.kind = 'DeployedServicePackage'
