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

from .audio_analyzer_preset import AudioAnalyzerPreset


class VideoAnalyzerPreset(AudioAnalyzerPreset):
    """A video analyzer preset that extracts insights (rich metadata) from both
    audio and video, and outputs a JSON format file.

    All required parameters must be populated in order to send to Azure.

    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param audio_language: The language for the audio payload in the input
     using the BCP-47 format of 'language tag-region' (e.g: 'en-US').  The list
     of supported languages are English ('en-US' and 'en-GB'), Spanish ('es-ES'
     and 'es-MX'), French ('fr-FR'), Italian ('it-IT'), Japanese ('ja-JP'),
     Portuguese ('pt-BR'), Chinese ('zh-CN'), German ('de-DE'), Arabic ('ar-EG'
     and 'ar-SY'), Russian ('ru-RU'), Hindi ('hi-IN'), and Korean ('ko-KR'). If
     you know the language of your content, it is recommended that you specify
     it. If the language isn't specified or set to null, automatic language
     detection will choose the first language detected and process with the
     selected language for the duration of the file. This language detection
     feature currently supports English, Chinese, French, German, Italian,
     Japanese, Spanish, Russian, and Portuguese. It does not currently support
     dynamically switching between languages after the first language is
     detected. The automatic detection works best with audio recordings with
     clearly discernable speech. If automatic detection fails to find the
     language, transcription would fallback to 'en-US'."
    :type audio_language: str
    :param insights_to_extract: Defines the type of insights that you want the
     service to generate. The allowed values are 'AudioInsightsOnly',
     'VideoInsightsOnly', and 'AllInsights'. The default is AllInsights. If you
     set this to AllInsights and the input is audio only, then only audio
     insights are generated. Similarly if the input is video only, then only
     video insights are generated. It is recommended that you not use
     AudioInsightsOnly if you expect some of your inputs to be video only; or
     use VideoInsightsOnly if you expect some of your inputs to be audio only.
     Your Jobs in such conditions would error out. Possible values include:
     'AudioInsightsOnly', 'VideoInsightsOnly', 'AllInsights'
    :type insights_to_extract: str or ~azure.mgmt.media.models.InsightsType
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'audio_language': {'key': 'audioLanguage', 'type': 'str'},
        'insights_to_extract': {'key': 'insightsToExtract', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(VideoAnalyzerPreset, self).__init__(**kwargs)
        self.insights_to_extract = kwargs.get('insights_to_extract', None)
        self.odatatype = '#Microsoft.Media.VideoAnalyzerPreset'
