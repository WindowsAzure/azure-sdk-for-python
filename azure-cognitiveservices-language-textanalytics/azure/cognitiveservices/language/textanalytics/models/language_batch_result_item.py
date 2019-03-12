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


class LanguageBatchResultItem(Model):
    """LanguageBatchResultItem.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Unique document identifier.
    :vartype id: str
    :ivar detected_languages: A list of extracted languages.
    :vartype detected_languages:
     list[~azure.cognitiveservices.language.textanalytics.models.DetectedLanguage]
    """

    _validation = {
        'id': {'readonly': True},
        'detected_languages': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'detected_languages': {'key': 'detectedLanguages', 'type': '[DetectedLanguage]'},
    }

    def __init__(self):
        super(LanguageBatchResultItem, self).__init__()
        self.id = None
        self.detected_languages = None
