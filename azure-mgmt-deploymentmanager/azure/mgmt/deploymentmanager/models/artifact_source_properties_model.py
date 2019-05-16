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


class ArtifactSourcePropertiesModel(Model):
    """The properties that define the source location where the artifacts are
    located.

    All required parameters must be populated in order to send to Azure.

    :param source_type: Required. The type of artifact source used.
    :type source_type: str
    :param artifact_root: The path from the location that the 'authentication'
     property [say, a SAS URI to the blob container] refers to, to the location
     of the artifacts. This can be used to differentiate different versions of
     the artifacts. Or, different types of artifacts like binaries or
     templates. The location referenced by the authentication property
     concatenated with this optional artifactRoot path forms the artifact
     source location where the artifacts are expected to be found.
    :type artifact_root: str
    :param authentication: Required. The authentication method to use to
     access the artifact source.
    :type authentication: ~azure.mgmt.deploymentmanager.models.Authentication
    """

    _validation = {
        'source_type': {'required': True},
        'authentication': {'required': True},
    }

    _attribute_map = {
        'source_type': {'key': 'sourceType', 'type': 'str'},
        'artifact_root': {'key': 'artifactRoot', 'type': 'str'},
        'authentication': {'key': 'authentication', 'type': 'Authentication'},
    }

    def __init__(self, **kwargs):
        super(ArtifactSourcePropertiesModel, self).__init__(**kwargs)
        self.source_type = kwargs.get('source_type', None)
        self.artifact_root = kwargs.get('artifact_root', None)
        self.authentication = kwargs.get('authentication', None)
