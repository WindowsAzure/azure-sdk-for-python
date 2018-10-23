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


class Export(Model):
    """Export.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar platform: Possible values include: 'CoreML', 'TensorFlow',
     'DockerFile', 'ONNX'
    :vartype platform: str or
     ~azure.cognitiveservices.vision.customvision.training.models.ExportPlatform
    :ivar status: Possible values include: 'Exporting', 'Failed', 'Done'
    :vartype status: str or
     ~azure.cognitiveservices.vision.customvision.training.models.ExportStatusModel
    :ivar download_uri:
    :vartype download_uri: str
    :ivar flavor: Possible values include: 'Linux', 'Windows'
    :vartype flavor: str or
     ~azure.cognitiveservices.vision.customvision.training.models.ExportFlavor
    :ivar newer_version_available:
    :vartype newer_version_available: bool
    """

    _validation = {
        'platform': {'readonly': True},
        'status': {'readonly': True},
        'download_uri': {'readonly': True},
        'flavor': {'readonly': True},
        'newer_version_available': {'readonly': True},
    }

    _attribute_map = {
        'platform': {'key': 'platform', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'download_uri': {'key': 'downloadUri', 'type': 'str'},
        'flavor': {'key': 'flavor', 'type': 'str'},
        'newer_version_available': {'key': 'newerVersionAvailable', 'type': 'bool'},
    }

    def __init__(self, **kwargs) -> None:
        super(Export, self).__init__(**kwargs)
        self.platform = None
        self.status = None
        self.download_uri = None
        self.flavor = None
        self.newer_version_available = None
