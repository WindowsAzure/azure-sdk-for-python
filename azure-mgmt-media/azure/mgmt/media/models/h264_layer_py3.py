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

from .video_layer_py3 import VideoLayer


class H264Layer(VideoLayer):
    """Describes the settings to be used when encoding the input video into a
    desired output bitrate layer with the H.264 video codec.

    All required parameters must be populated in order to send to Azure.

    :param width: The width of the output video for this layer. The value can
     be absolute (in pixels) or relative (in percentage). For example 50% means
     the output video has half as many pixels in width as the input.
    :type width: str
    :param height: The height of the output video for this layer. The value
     can be absolute (in pixels) or relative (in percentage). For example 50%
     means the output video has half as many pixels in height as the input.
    :type height: str
    :param label: The alphanumeric label for this layer, which can be used in
     multiplexing different video and audio layers, or in naming the output
     file.
    :type label: str
    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param bitrate: The average bitrate in bits per second at which to encode
     the input video when generating this layer. This is a required field.
    :type bitrate: int
    :param max_bitrate: The maximum bitrate (in bits per second), at which the
     VBV buffer should be assumed to refill. If not specified, defaults to the
     same value as bitrate.
    :type max_bitrate: int
    :param b_frames: The number of B-frames to be used when encoding this
     layer.  If not specified, the encoder chooses an appropriate number based
     on the video profile and level.
    :type b_frames: int
    :param frame_rate: The frame rate (in frames per second) at which to
     encode this layer. The value can be in the form of M/N where M and N are
     integers (For example, 30000/1001), or in the form of a number (For
     example, 30, or 29.97). The encoder enforces constraints on allowed frame
     rates based on the profile and level. If it is not specified, the encoder
     will use the same frame rate as the input video.
    :type frame_rate: str
    :param slices: The number of slices to be used when encoding this layer.
     If not specified, default is zero, which means that encoder will use a
     single slice for each frame.
    :type slices: int
    :param adaptive_bframe: Whether or not adaptive B-frames are to be used
     when encoding this layer. If not specified, the encoder will turn it on
     whenever the video profile permits its use.
    :type adaptive_bframe: bool
    :param profile: Which profile of the H.264 standard should be used when
     encoding this layer. Default is Auto. Possible values include: 'Auto',
     'Baseline', 'Main', 'High', 'High422', 'High444'
    :type profile: str or ~azure.mgmt.media.models.H264VideoProfile
    :param level: Which level of the H.264 standard should be used when
     encoding this layer. The value can be Auto, or a number that matches the
     H.264 profile. If not specified, the default is Auto, which lets the
     encoder choose the Level that is appropriate for this layer.
    :type level: str
    :param buffer_window: The VBV buffer window length. The value should be in
     ISO 8601 format. The value should be in the range [0.1-100] seconds. The
     default is 5 seconds (for example, PT5S).
    :type buffer_window: timedelta
    :param reference_frames: The number of reference frames to be used when
     encoding this layer. If not specified, the encoder determines an
     appropriate number based on the encoder complexity setting.
    :type reference_frames: int
    :param entropy_mode: The entropy mode to be used for this layer. If not
     specified, the encoder chooses the mode that is appropriate for the
     profile and level. Possible values include: 'Cabac', 'Cavlc'
    :type entropy_mode: str or ~azure.mgmt.media.models.EntropyMode
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'width': {'key': 'width', 'type': 'str'},
        'height': {'key': 'height', 'type': 'str'},
        'label': {'key': 'label', 'type': 'str'},
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'bitrate': {'key': 'bitrate', 'type': 'int'},
        'max_bitrate': {'key': 'maxBitrate', 'type': 'int'},
        'b_frames': {'key': 'bFrames', 'type': 'int'},
        'frame_rate': {'key': 'frameRate', 'type': 'str'},
        'slices': {'key': 'slices', 'type': 'int'},
        'adaptive_bframe': {'key': 'adaptiveBFrame', 'type': 'bool'},
        'profile': {'key': 'profile', 'type': 'str'},
        'level': {'key': 'level', 'type': 'str'},
        'buffer_window': {'key': 'bufferWindow', 'type': 'duration'},
        'reference_frames': {'key': 'referenceFrames', 'type': 'int'},
        'entropy_mode': {'key': 'entropyMode', 'type': 'str'},
    }

    def __init__(self, *, width: str=None, height: str=None, label: str=None, bitrate: int=None, max_bitrate: int=None, b_frames: int=None, frame_rate: str=None, slices: int=None, adaptive_bframe: bool=None, profile=None, level: str=None, buffer_window=None, reference_frames: int=None, entropy_mode=None, **kwargs) -> None:
        super(H264Layer, self).__init__(width=width, height=height, label=label, bitrate=bitrate, max_bitrate=max_bitrate, b_frames=b_frames, frame_rate=frame_rate, slices=slices, adaptive_bframe=adaptive_bframe, **kwargs)
        self.profile = profile
        self.level = level
        self.buffer_window = buffer_window
        self.reference_frames = reference_frames
        self.entropy_mode = entropy_mode
        self.odatatype = '#Microsoft.Media.H264Layer'
