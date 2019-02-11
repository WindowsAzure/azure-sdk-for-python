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


class ApplyArtifactsRequest(Model):
    """Request body for applying artifacts to a virtual machine.

    :param artifacts: The list of artifacts to apply.
    :type artifacts:
     list[~azure.mgmt.devtestlabs.models.ArtifactInstallProperties]
    """

    _attribute_map = {
        'artifacts': {'key': 'artifacts', 'type': '[ArtifactInstallProperties]'},
    }

    def __init__(self, **kwargs):
        super(ApplyArtifactsRequest, self).__init__(**kwargs)
        self.artifacts = kwargs.get('artifacts', None)
