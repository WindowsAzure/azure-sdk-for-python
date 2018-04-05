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


class Image(Model):
    """Image model to be sent as JSON.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id:
    :vartype id: str
    :ivar created:
    :vartype created: datetime
    :ivar width:
    :vartype width: int
    :ivar height:
    :vartype height: int
    :ivar image_uri:
    :vartype image_uri: str
    :ivar thumbnail_uri:
    :vartype thumbnail_uri: str
    :ivar tags:
    :vartype tags:
     list[~azure.cognitiveservices.vision.customvision.training.models.ImageTag]
    :ivar predictions:
    :vartype predictions:
     list[~azure.cognitiveservices.vision.customvision.training.models.PredictionTag]
    """

    _validation = {
        'id': {'readonly': True},
        'created': {'readonly': True},
        'width': {'readonly': True},
        'height': {'readonly': True},
        'image_uri': {'readonly': True},
        'thumbnail_uri': {'readonly': True},
        'tags': {'readonly': True},
        'predictions': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'Id', 'type': 'str'},
        'created': {'key': 'Created', 'type': 'iso-8601'},
        'width': {'key': 'Width', 'type': 'int'},
        'height': {'key': 'Height', 'type': 'int'},
        'image_uri': {'key': 'ImageUri', 'type': 'str'},
        'thumbnail_uri': {'key': 'ThumbnailUri', 'type': 'str'},
        'tags': {'key': 'Tags', 'type': '[ImageTag]'},
        'predictions': {'key': 'Predictions', 'type': '[PredictionTag]'},
    }

    def __init__(self, **kwargs):
        super(Image, self).__init__(**kwargs)
        self.id = None
        self.created = None
        self.width = None
        self.height = None
        self.image_uri = None
        self.thumbnail_uri = None
        self.tags = None
        self.predictions = None
