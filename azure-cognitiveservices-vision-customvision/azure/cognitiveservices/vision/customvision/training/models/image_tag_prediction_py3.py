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


class ImageTagPrediction(Model):
    """ImageTagPrediction.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar tag_id:
    :vartype tag_id: str
    :ivar tag:
    :vartype tag: str
    :ivar probability:
    :vartype probability: float
    """

    _validation = {
        'tag_id': {'readonly': True},
        'tag': {'readonly': True},
        'probability': {'readonly': True},
    }

    _attribute_map = {
        'tag_id': {'key': 'TagId', 'type': 'str'},
        'tag': {'key': 'Tag', 'type': 'str'},
        'probability': {'key': 'Probability', 'type': 'float'},
    }

    def __init__(self, **kwargs) -> None:
        super(ImageTagPrediction, self).__init__(**kwargs)
        self.tag_id = None
        self.tag = None
        self.probability = None
