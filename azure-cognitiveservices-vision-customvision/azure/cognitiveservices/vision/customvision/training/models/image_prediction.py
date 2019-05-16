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


class ImagePrediction(Model):
    """Result of an image prediction request.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Prediction Id.
    :vartype id: str
    :ivar project: Project Id.
    :vartype project: str
    :ivar iteration: Iteration Id.
    :vartype iteration: str
    :ivar created: Date this prediction was created.
    :vartype created: datetime
    :ivar predictions: List of predictions.
    :vartype predictions:
     list[~azure.cognitiveservices.vision.customvision.training.models.Prediction]
    """

    _validation = {
        'id': {'readonly': True},
        'project': {'readonly': True},
        'iteration': {'readonly': True},
        'created': {'readonly': True},
        'predictions': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'project': {'key': 'project', 'type': 'str'},
        'iteration': {'key': 'iteration', 'type': 'str'},
        'created': {'key': 'created', 'type': 'iso-8601'},
        'predictions': {'key': 'predictions', 'type': '[Prediction]'},
    }

    def __init__(self, **kwargs):
        super(ImagePrediction, self).__init__(**kwargs)
        self.id = None
        self.project = None
        self.iteration = None
        self.created = None
        self.predictions = None
