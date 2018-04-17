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

from .layer import Layer


class VideoLayer(Layer):
    """Describes the settings to be used when encoding the input video into a
    desired output bitrate layer.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: H264Layer

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
    }

    _subtype_map = {
        'odatatype': {'#Microsoft.Media.H264Layer': 'H264Layer'}
    }

    def __init__(self, *, width: str=None, height: str=None, label: str=None, bitrate: int=None, max_bitrate: int=None, b_frames: int=None, frame_rate: str=None, slices: int=None, adaptive_bframe: bool=None, **kwargs) -> None:
        super(VideoLayer, self).__init__(width=width, height=height, label=label, **kwargs)
        self.bitrate = bitrate
        self.max_bitrate = max_bitrate
        self.b_frames = b_frames
        self.frame_rate = frame_rate
        self.slices = slices
        self.adaptive_bframe = adaptive_bframe
        self.odatatype = '#Microsoft.Media.VideoLayer'
