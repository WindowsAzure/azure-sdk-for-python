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

from .overlay import Overlay


class VideoOverlay(Overlay):
    """Describes the properties of a video overlay.

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
    :param position: The location in the input video where the overlay is
     applied.
    :type position: ~azure.mgmt.media.models.Rectangle
    :param opacity: The opacity of the overlay. This is a value in the range
     [0 - 1.0]. Default is 1.0 which mean the overlay is opaque.
    :type opacity: float
    :param crop_rectangle: An optional rectangular window used to crop the
     overlay image or video.
    :type crop_rectangle: ~azure.mgmt.media.models.Rectangle
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
        'position': {'key': 'position', 'type': 'Rectangle'},
        'opacity': {'key': 'opacity', 'type': 'float'},
        'crop_rectangle': {'key': 'cropRectangle', 'type': 'Rectangle'},
    }

    def __init__(self, *, input_label: str=None, start=None, end=None, fade_in_duration=None, fade_out_duration=None, audio_gain_level: float=None, position=None, opacity: float=None, crop_rectangle=None, **kwargs) -> None:
        super(VideoOverlay, self).__init__(input_label=input_label, start=start, end=end, fade_in_duration=fade_in_duration, fade_out_duration=fade_out_duration, audio_gain_level=audio_gain_level, **kwargs)
        self.position = position
        self.opacity = opacity
        self.crop_rectangle = crop_rectangle
        self.odatatype = '#Microsoft.Media.VideoOverlay'
