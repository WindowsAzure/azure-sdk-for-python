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


class PredictionQuery(Model):
    """PredictionQuery.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar results:
    :vartype results:
     list[~azure.cognitiveservices.vision.customvision.training.models.Prediction]
    :ivar token:
    :vartype token:
     ~azure.cognitiveservices.vision.customvision.training.models.PredictionQueryToken
    """

    _validation = {
        'results': {'readonly': True},
        'token': {'readonly': True},
    }

    _attribute_map = {
        'results': {'key': 'Results', 'type': '[Prediction]'},
        'token': {'key': 'Token', 'type': 'PredictionQueryToken'},
    }

    def __init__(self, **kwargs) -> None:
        super(PredictionQuery, self).__init__(**kwargs)
        self.results = None
        self.token = None
