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


class Overlay(Model):
    """Base type for all overlays - image, audio or video.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AudioOverlay, VideoOverlay

    All required parameters must be populated in order to send to Azure.

    :param input_label: The label of the job input which is to be used as an
     overlay. The Input must specify exactly one file. You can specify an image
     file in JPG or PNG formats, or an audio file (such as a WAV, MP3, WMA or
     M4A file), or a video file. See https://aka.ms/mesformats for the complete
     list of supported audio and video file formats.
    :type input_label: str
    :param start: The start position, with reference to the input video, at
     which the overlay starts. The value should be in ISO 8601 format. For
     example, PT05S to start the overlay at 5 seconds in to the input video. If
     not specified the overlay starts from the beginning of the input video.
    :type start: timedelta
    :param end: The position in the input video at which the overlay ends. The
     value should be in ISO 8601 duration format. For example, PT30S to end the
     overlay at 30 seconds in to the input video. If not specified the overlay
     will be applied until the end of the input video if inputLoop is true.
     Else, if inputLoop is false, then overlay will last as long as the
     duration of the overlay media.
    :type end: timedelta
    :param fade_in_duration: The duration over which the overlay fades in onto
     the input video. The value should be in ISO 8601 duration format. If not
     specified the default behavior is to have no fade in (same as PT0S).
    :type fade_in_duration: timedelta
    :param fade_out_duration: The duration over which the overlay fades out of
     the input video. The value should be in ISO 8601 duration format. If not
     specified the default behavior is to have no fade out (same as PT0S).
    :type fade_out_duration: timedelta
    :param audio_gain_level: The gain level of audio in the overlay. The value
     should be in the range [0, 1.0]. The default is 1.0.
    :type audio_gain_level: float
    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'input_label': {'key': 'inputLabel', 'type': 'str'},
        'start': {'key': 'start', 'type': 'duration'},
        'end': {'key': 'end', 'type': 'duration'},
        'fade_in_duration': {'key': 'fadeInDuration', 'type': 'duration'},
        'fade_out_duration': {'key': 'fadeOutDuration', 'type': 'duration'},
        'audio_gain_level': {'key': 'audioGainLevel', 'type': 'float'},
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
    }

    _subtype_map = {
        'odatatype': {'#Microsoft.Media.AudioOverlay': 'AudioOverlay', '#Microsoft.Media.VideoOverlay': 'VideoOverlay'}
    }

    def __init__(self, **kwargs):
        super(Overlay, self).__init__(**kwargs)
        self.input_label = kwargs.get('input_label', None)
        self.start = kwargs.get('start', None)
        self.end = kwargs.get('end', None)
        self.fade_in_duration = kwargs.get('fade_in_duration', None)
        self.fade_out_duration = kwargs.get('fade_out_duration', None)
        self.audio_gain_level = kwargs.get('audio_gain_level', None)
        self.odatatype = None
