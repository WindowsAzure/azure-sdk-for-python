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

from .azure_resource_base_py3 import AzureResourceBase


class AssignmentOperation(AzureResourceBase):
    """Represents underlying deployment detail for each update to the blueprint
    assignment.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: String Id used to locate any resource on Azure.
    :vartype id: str
    :ivar type: Type of this resource.
    :vartype type: str
    :ivar name: Name of this resource.
    :vartype name: str
    :param blueprint_version: The published version of the blueprint
     definition used for the blueprint assignment operation.
    :type blueprint_version: str
    :param assignment_state: State of this blueprint assignment operation.
    :type assignment_state: str
    :param time_created: Create time of this blueprint assignment operation.
    :type time_created: str
    :param time_started: Start time of the underlying deployment.
    :type time_started: str
    :param time_finished: Finish time of the overall underlying deployments.
    :type time_finished: str
    :param deployments: List of jobs in this blueprint assignment operation.
    :type deployments:
     list[~azure.mgmt.blueprint.models.AssignmentDeploymentJob]
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'blueprint_version': {'key': 'properties.blueprintVersion', 'type': 'str'},
        'assignment_state': {'key': 'properties.assignmentState', 'type': 'str'},
        'time_created': {'key': 'properties.timeCreated', 'type': 'str'},
        'time_started': {'key': 'properties.timeStarted', 'type': 'str'},
        'time_finished': {'key': 'properties.timeFinished', 'type': 'str'},
        'deployments': {'key': 'properties.deployments', 'type': '[AssignmentDeploymentJob]'},
    }

    def __init__(self, *, blueprint_version: str=None, assignment_state: str=None, time_created: str=None, time_started: str=None, time_finished: str=None, deployments=None, **kwargs) -> None:
        super(AssignmentOperation, self).__init__(**kwargs)
        self.blueprint_version = blueprint_version
        self.assignment_state = assignment_state
        self.time_created = time_created
        self.time_started = time_started
        self.time_finished = time_finished
        self.deployments = deployments
