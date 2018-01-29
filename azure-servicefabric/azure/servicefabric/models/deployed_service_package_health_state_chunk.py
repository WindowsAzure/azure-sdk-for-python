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

from .entity_health_state_chunk import EntityHealthStateChunk


class DeployedServicePackageHealthStateChunk(EntityHealthStateChunk):
    """Represents the health state chunk of a deployed service package, which
    contains the service manifest name and the service package aggregated
    health state.
    .

    :param health_state: Possible values include: 'Invalid', 'Ok', 'Warning',
     'Error', 'Unknown'
    :type health_state: str or ~azure.servicefabric.models.enum
    :param service_manifest_name:
    :type service_manifest_name: str
    :param service_package_activation_id:
    :type service_package_activation_id: str
    """

    _attribute_map = {
        'health_state': {'key': 'HealthState', 'type': 'str'},
        'service_manifest_name': {'key': 'ServiceManifestName', 'type': 'str'},
        'service_package_activation_id': {'key': 'ServicePackageActivationId', 'type': 'str'},
    }

    def __init__(self, health_state=None, service_manifest_name=None, service_package_activation_id=None):
        super(DeployedServicePackageHealthStateChunk, self).__init__(health_state=health_state)
        self.service_manifest_name = service_manifest_name
        self.service_package_activation_id = service_package_activation_id
