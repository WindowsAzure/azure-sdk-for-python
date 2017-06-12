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


class ArtifactDeploymentStatusProperties(Model):
    """Properties of an artifact deployment.

    :param deployment_status: The deployment status of the artifact.
    :type deployment_status: str
    :param artifacts_applied: The total count of the artifacts that were
     successfully applied.
    :type artifacts_applied: int
    :param total_artifacts: The total count of the artifacts that were
     tentatively applied.
    :type total_artifacts: int
    """ 

    _attribute_map = {
        'deployment_status': {'key': 'deploymentStatus', 'type': 'str'},
        'artifacts_applied': {'key': 'artifactsApplied', 'type': 'int'},
        'total_artifacts': {'key': 'totalArtifacts', 'type': 'int'},
    }

    def __init__(self, deployment_status=None, artifacts_applied=None, total_artifacts=None):
        self.deployment_status = deployment_status
        self.artifacts_applied = artifacts_applied
        self.total_artifacts = total_artifacts
