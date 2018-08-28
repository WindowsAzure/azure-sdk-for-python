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

from .preset_py3 import Preset


class BuiltInStandardEncoderPreset(Preset):
    """Describes a built-in preset for encoding the input video with the Standard
    Encoder.

    All required parameters must be populated in order to send to Azure.

    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param preset_name: Required. The built-in preset to be used for encoding
     videos. Possible values include: 'AdaptiveStreaming',
     'AACGoodQualityAudio', 'H264MultipleBitrate1080p',
     'H264MultipleBitrate720p', 'H264MultipleBitrateSD'
    :type preset_name: str or ~azure.mgmt.media.models.EncoderNamedPreset
    """

    _validation = {
        'odatatype': {'required': True},
        'preset_name': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'preset_name': {'key': 'presetName', 'type': 'EncoderNamedPreset'},
    }

    def __init__(self, *, preset_name, **kwargs) -> None:
        super(BuiltInStandardEncoderPreset, self).__init__(**kwargs)
        self.preset_name = preset_name
        self.odatatype = '#Microsoft.Media.BuiltInStandardEncoderPreset'
