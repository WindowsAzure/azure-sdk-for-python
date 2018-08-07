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

from .multi_bitrate_format import MultiBitrateFormat


class Mp4Format(MultiBitrateFormat):
    """Describes the properties for an output ISO MP4 file.

    All required parameters must be populated in order to send to Azure.

    :param filename_pattern: The pattern of the file names for the generated
     output files. The following macros are supported in the file name:
     {Basename} - The base name of the input video {Extension} - The
     appropriate extension for this format. {Label} - The label assigned to the
     codec/layer. {Index} - A unique index for thumbnails. Only applicable to
     thumbnails. {Bitrate} - The audio/video bitrate. Not applicable to
     thumbnails. {Codec} - The type of the audio/video codec. Any unsubstituted
     macros will be collapsed and removed from the filename.
    :type filename_pattern: str
    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param output_files: The list of output files to produce.  Each entry in
     the list is a set of audio and video layer labels to be muxed together .
    :type output_files: list[~azure.mgmt.media.models.OutputFile]
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'filename_pattern': {'key': 'filenamePattern', 'type': 'str'},
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'output_files': {'key': 'outputFiles', 'type': '[OutputFile]'},
    }

    def __init__(self, **kwargs):
        super(Mp4Format, self).__init__(**kwargs)
        self.odatatype = '#Microsoft.Media.Mp4Format'
