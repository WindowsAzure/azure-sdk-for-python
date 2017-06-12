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


class ArtifactInstallProperties(Model):
    """Properties of an artifact.

    :param artifact_id: The artifact's identifier.
    :type artifact_id: str
    :param parameters: The parameters of the artifact.
    :type parameters: list of :class:`ArtifactParameterProperties
     <azure.mgmt.devtestlabs.models.ArtifactParameterProperties>`
    """ 

    _attribute_map = {
        'artifact_id': {'key': 'artifactId', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '[ArtifactParameterProperties]'},
    }

    def __init__(self, artifact_id=None, parameters=None):
        self.artifact_id = artifact_id
        self.parameters = parameters
