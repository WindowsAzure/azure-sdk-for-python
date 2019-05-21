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


class Occlusion(Model):
    """Properties describing occlusions on a given face.

    :param forehead_occluded: A boolean value indicating whether forehead is
     occluded.
    :type forehead_occluded: bool
    :param eye_occluded: A boolean value indicating whether eyes are occluded.
    :type eye_occluded: bool
    :param mouth_occluded: A boolean value indicating whether the mouth is
     occluded.
    :type mouth_occluded: bool
    """

    _attribute_map = {
        'forehead_occluded': {'key': 'foreheadOccluded', 'type': 'bool'},
        'eye_occluded': {'key': 'eyeOccluded', 'type': 'bool'},
        'mouth_occluded': {'key': 'mouthOccluded', 'type': 'bool'},
    }

    def __init__(self, *, forehead_occluded: bool=None, eye_occluded: bool=None, mouth_occluded: bool=None, **kwargs) -> None:
        super(Occlusion, self).__init__(**kwargs)
        self.forehead_occluded = forehead_occluded
        self.eye_occluded = eye_occluded
        self.mouth_occluded = mouth_occluded
