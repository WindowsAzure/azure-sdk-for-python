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
    """The evaluation of the deployed service package health.

    :param description:
    :type description: str
    :param aggregated_health_state: Possible values include: 'Invalid', 'Ok',
     'Warning', 'Error', 'Unknown'
    :type aggregated_health_state: str or :class:`enum
     <azure.fabric.models.enum>`
    :param kind: Polymorphic Discriminator
    :type kind: str
    :param application_name:
    :type application_name: str
    :param node_name:
    :type node_name: str
    :param service_manifest_name:
    :type service_manifest_name: str
    :param unhealthy_evaluations:
    :type unhealthy_evaluations: list of :class:`UnhealthyEvaluation
     <azure.fabric.models.UnhealthyEvaluation>`
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'description': {'key': 'Description', 'type': 'str'},
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'application_name': {'key': 'ApplicationName', 'type': 'str'},
        'node_name': {'key': 'NodeName', 'type': 'str'},
        'service_manifest_name': {'key': 'ServiceManifestName', 'type': 'str'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': '[UnhealthyEvaluation]'},
    }

    def __init__(self, description=None, aggregated_health_state=None, application_name=None, node_name=None, service_manifest_name=None, unhealthy_evaluations=None):
        super(DeployedServicePackageHealthEvaluation, self).__init__(description=description, aggregated_health_state=aggregated_health_state)
        self.application_name = application_name
        self.node_name = node_name
        self.service_manifest_name = service_manifest_name
        self.unhealthy_evaluations = unhealthy_evaluations
        self.kind = 'DeployedServicePackage'
