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

from .service_unit_properties import ServiceUnitProperties


class ServiceUnit(ServiceUnitProperties):
    """Defines a service unit.

    All required parameters must be populated in order to send to Azure.

    :param target_resource_group: Required. The Azure Resource Group to which
     the resources in the service unit belong to or should be deployed to.
    :type target_resource_group: str
    :param deployment_mode: Required. Describes the type of ARM deployment to
     be performed on the resource. Possible values include: 'Incremental',
     'Complete'
    :type deployment_mode: str or
     ~azure.mgmt.deploymentmanager.models.DeploymentMode
    :param artifacts: The artifacts for the service unit.
    :type artifacts: ~azure.mgmt.deploymentmanager.models.ServiceUnitArtifacts
    :param name: Name of the service unit.
    :type name: str
    :param steps: Detailed step information, if present.
    :type steps: list[~azure.mgmt.deploymentmanager.models.RolloutStep]
    """

    _validation = {
        'target_resource_group': {'required': True},
        'deployment_mode': {'required': True},
    }

    _attribute_map = {
        'target_resource_group': {'key': 'targetResourceGroup', 'type': 'str'},
        'deployment_mode': {'key': 'deploymentMode', 'type': 'DeploymentMode'},
        'artifacts': {'key': 'artifacts', 'type': 'ServiceUnitArtifacts'},
        'name': {'key': 'name', 'type': 'str'},
        'steps': {'key': 'steps', 'type': '[RolloutStep]'},
    }

    def __init__(self, **kwargs):
        super(ServiceUnit, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.steps = kwargs.get('steps', None)
