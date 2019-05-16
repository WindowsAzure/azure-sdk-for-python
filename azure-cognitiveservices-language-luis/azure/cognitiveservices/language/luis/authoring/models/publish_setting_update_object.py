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


class PublishSettingUpdateObject(Model):
    """Object model for updating an application's publish settings.

    :param sentiment_analysis: Setting sentiment analysis as true returns the
     Sentiment of the input utterance along with the response
    :type sentiment_analysis: bool
    :param speech: Setting speech as public enables speech priming in your app
    :type speech: bool
    :param spell_checker: Setting spell checker as public enables spell
     checking the input utterance.
    :type spell_checker: bool
    """

    _attribute_map = {
        'sentiment_analysis': {'key': 'sentimentAnalysis', 'type': 'bool'},
        'speech': {'key': 'speech', 'type': 'bool'},
        'spell_checker': {'key': 'spellChecker', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(PublishSettingUpdateObject, self).__init__(**kwargs)
        self.sentiment_analysis = kwargs.get('sentiment_analysis', None)
        self.speech = kwargs.get('speech', None)
        self.spell_checker = kwargs.get('spell_checker', None)
