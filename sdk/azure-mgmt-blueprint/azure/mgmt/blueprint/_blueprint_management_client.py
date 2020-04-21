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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer

from ._configuration import BlueprintManagementClientConfiguration
from .operations import BlueprintsOperations
from .operations import ArtifactsOperations
from .operations import PublishedBlueprintsOperations
from .operations import PublishedArtifactsOperations
from .operations import AssignmentsOperations
from .operations import AssignmentOperations
from . import models


class BlueprintManagementClient(SDKClient):
    """Blueprint Client

    :ivar config: Configuration for client.
    :vartype config: BlueprintManagementClientConfiguration

    :ivar blueprints: Blueprints operations
    :vartype blueprints: azure.mgmt.blueprint.operations.BlueprintsOperations
    :ivar artifacts: Artifacts operations
    :vartype artifacts: azure.mgmt.blueprint.operations.ArtifactsOperations
    :ivar published_blueprints: PublishedBlueprints operations
    :vartype published_blueprints: azure.mgmt.blueprint.operations.PublishedBlueprintsOperations
    :ivar published_artifacts: PublishedArtifacts operations
    :vartype published_artifacts: azure.mgmt.blueprint.operations.PublishedArtifactsOperations
    :ivar assignments: Assignments operations
    :vartype assignments: azure.mgmt.blueprint.operations.AssignmentsOperations
    :ivar assignment_operations: AssignmentOperations operations
    :vartype assignment_operations: azure.mgmt.blueprint.operations.AssignmentOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, base_url=None):

        self.config = BlueprintManagementClientConfiguration(credentials, base_url)
        super(BlueprintManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-11-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.blueprints = BlueprintsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.artifacts = ArtifactsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.published_blueprints = PublishedBlueprintsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.published_artifacts = PublishedArtifactsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.assignments = AssignmentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.assignment_operations = AssignmentOperations(
            self._client, self.config, self._serialize, self._deserialize)
