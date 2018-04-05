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

    :ivar platform: Possible values include: 'CoreML', 'TensorFlow'
    :vartype platform: str or
     ~azure.cognitiveservices.vision.customvision.training.models.enum
    :ivar status: Possible values include: 'Exporting', 'Failed', 'Done'
    :vartype status: str or
     ~azure.cognitiveservices.vision.customvision.training.models.enum
    :ivar download_uri:
    :vartype download_uri: str
    """

    _validation = {
        'platform': {'readonly': True},
        'status': {'readonly': True},
        'download_uri': {'readonly': True},
    }

    _attribute_map = {
        'platform': {'key': 'Platform', 'type': 'str'},
        'status': {'key': 'Status', 'type': 'str'},
        'download_uri': {'key': 'DownloadUri', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(Export, self).__init__(**kwargs)
        self.platform = None
        self.status = None
        self.download_uri = None
