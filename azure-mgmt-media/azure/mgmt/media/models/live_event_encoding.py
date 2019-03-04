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


class LiveEventEncoding(Model):
    """The Live Event encoding.

    :param encoding_type: The encoding type for Live Event.  This value is
     specified at creation time and cannot be updated. Possible values include:
     'None', 'Basic', 'Standard'
    :type encoding_type: str or ~azure.mgmt.media.models.LiveEventEncodingType
    :param preset_name: The encoding preset name.  This value is specified at
     creation time and cannot be updated.
    :type preset_name: str
    """

    _attribute_map = {
        'encoding_type': {'key': 'encodingType', 'type': 'LiveEventEncodingType'},
        'preset_name': {'key': 'presetName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(LiveEventEncoding, self).__init__(**kwargs)
        self.encoding_type = kwargs.get('encoding_type', None)
        self.preset_name = kwargs.get('preset_name', None)
