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


class JSONUtterance(Model):
    """Exported Model - Utterance that was used to train the model.

    :param text: The utterance.
    :type text: str
    :param intent: The matched intent.
    :type intent: str
    :param entities: The matched entities.
    :type entities:
     list[~azure.cognitiveservices.language.luis.authoring.models.JSONEntity]
    """

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'intent': {'key': 'intent', 'type': 'str'},
        'entities': {'key': 'entities', 'type': '[JSONEntity]'},
    }

    def __init__(self, **kwargs):
        super(JSONUtterance, self).__init__(**kwargs)
        self.text = kwargs.get('text', None)
        self.intent = kwargs.get('intent', None)
        self.entities = kwargs.get('entities', None)
