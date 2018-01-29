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


class ApplicationArtifact(Model):
    """Managed application artifact.

    :param name: The managed application artifact name.
    :type name: str
    :param uri: The managed application artifact blob uri.
    :type uri: str
    :param type: The managed application artifact type. Possible values
     include: 'Template', 'Custom'
    :type type: str or
     ~azure.mgmt.resource.managedapplications.models.ApplicationArtifactType
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'uri': {'key': 'uri', 'type': 'str'},
        'type': {'key': 'type', 'type': 'ApplicationArtifactType'},
    }

    def __init__(self, name=None, uri=None, type=None):
        super(ApplicationArtifact, self).__init__()
        self.name = name
        self.uri = uri
        self.type = type
