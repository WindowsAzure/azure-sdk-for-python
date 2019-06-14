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


class LiveEventTranscription(Model):
    """Describes the transcription tracks in the output of a Live Event, generated
    using speech-to-text transcription.

    :param language: Specifies the language (locale) used for speech-to-text
     transcription � it should match the spoken language in the audio track.
     The value should be in BCP-47 format of 'language tag-region' (e.g:
     'en-US'). The list of supported languages are 'en-US' and 'en-GB'.
    :type language: str
    :param input_track_selection: Provides a mechanism to select the audio
     track in the input live feed, to which speech-to-text transcription is
     applied.
    :type input_track_selection:
     list[~azure.mgmt.media.models.LiveEventInputTrackSelection]
    :param output_transcription_track: Describes a transcription track in the
     output of a Live Event, generated using speech-to-text transcription.
    :type output_transcription_track:
     ~azure.mgmt.media.models.LiveEventOutputTranscriptionTrack
    """

    _attribute_map = {
        'language': {'key': 'language', 'type': 'str'},
        'input_track_selection': {'key': 'inputTrackSelection', 'type': '[LiveEventInputTrackSelection]'},
        'output_transcription_track': {'key': 'outputTranscriptionTrack', 'type': 'LiveEventOutputTranscriptionTrack'},
    }

    def __init__(self, *, language: str=None, input_track_selection=None, output_transcription_track=None, **kwargs) -> None:
        super(LiveEventTranscription, self).__init__(**kwargs)
        self.language = language
        self.input_track_selection = input_track_selection
        self.output_transcription_track = output_transcription_track
