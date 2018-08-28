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

from .audio_analyzer_preset_py3 import AudioAnalyzerPreset


class VideoAnalyzerPreset(AudioAnalyzerPreset):
    """A video analyzer preset that extracts insights (rich metadata) from both
    audio and video, and outputs a JSON format file.

    All required parameters must be populated in order to send to Azure.

    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param audio_language: The language for the audio payload in the input
     using the BCP-47 format of 'language tag-region' (e.g: 'en-US'). The list
     of supported languages are, 'en-US', 'en-GB', 'es-ES', 'es-MX', 'fr-FR',
     'it-IT', 'ja-JP', 'pt-BR', 'zh-CN'.
    :type audio_language: str
    :param audio_insights_only: Whether to only extract audio insights when
     processing a video file.
    :type audio_insights_only: bool
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'audio_language': {'key': 'audioLanguage', 'type': 'str'},
        'audio_insights_only': {'key': 'audioInsightsOnly', 'type': 'bool'},
    }

    def __init__(self, *, audio_language: str=None, audio_insights_only: bool=None, **kwargs) -> None:
        super(VideoAnalyzerPreset, self).__init__(audio_language=audio_language, **kwargs)
        self.audio_insights_only = audio_insights_only
        self.odatatype = '#Microsoft.Media.VideoAnalyzerPreset'
