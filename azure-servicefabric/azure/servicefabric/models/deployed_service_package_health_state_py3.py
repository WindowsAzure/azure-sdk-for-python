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

from .entity_health_state import EntityHealthState


class DeployedServicePackageHealthState(EntityHealthState):
    """Represents the health state of a deployed service package, containing the
    entity identifier and the aggregated health state.

    :param aggregated_health_state: The health state of a Service Fabric
     entity such as Cluster, Node, Application, Service, Partition, Replica
     etc. Possible values include: 'Invalid', 'Ok', 'Warning', 'Error',
     'Unknown'
    :type aggregated_health_state: str or
     ~azure.servicefabric.models.HealthState
    :param node_name: Name of the node on which the service package is
     deployed.
    :type node_name: str
    :param application_name: The name of the application, including the
     'fabric:' URI scheme.
    :type application_name: str
    :param service_manifest_name: Name of the manifest describing the service
     package.
    :type service_manifest_name: str
    :param service_package_activation_id: The ActivationId of a deployed
     service package. If ServicePackageActivationMode specified at the time of
     creating the service
     is 'SharedProcess' (or if it is not specified, in which case it defaults
     to 'SharedProcess'), then value of ServicePackageActivationId
     is always an empty string.
    :type service_package_activation_id: str
    """

    _attribute_map = {
        'aggregated_health_state': {'key': 'AggregatedHealthState', 'type': 'str'},
        'node_name': {'key': 'NodeName', 'type': 'str'},
        'application_name': {'key': 'ApplicationName', 'type': 'str'},
        'service_manifest_name': {'key': 'ServiceManifestName', 'type': 'str'},
        'service_package_activation_id': {'key': 'ServicePackageActivationId', 'type': 'str'},
    }

    def __init__(self, *, aggregated_health_state=None, node_name: str=None, application_name: str=None, service_manifest_name: str=None, service_package_activation_id: str=None, **kwargs) -> None:
        super(DeployedServicePackageHealthState, self).__init__(aggregated_health_state=aggregated_health_state, **kwargs)
        self.node_name = node_name
        self.application_name = application_name
        self.service_manifest_name = service_manifest_name
        self.service_package_activation_id = service_package_activation_id
