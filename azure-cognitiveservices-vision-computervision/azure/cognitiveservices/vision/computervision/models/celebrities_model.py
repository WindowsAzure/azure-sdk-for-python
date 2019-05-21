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


class CelebritiesModel(Model):
    """An object describing possible celebrity identification.

    :param name: Name of the celebrity.
    :type name: str
    :param confidence: Confidence level for the celebrity recognition as a
     value ranging from 0 to 1.
    :type confidence: float
    :param face_rectangle: Location of the identified face in the image.
    :type face_rectangle:
     ~azure.cognitiveservices.vision.computervision.models.FaceRectangle
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'confidence': {'key': 'confidence', 'type': 'float'},
        'face_rectangle': {'key': 'faceRectangle', 'type': 'FaceRectangle'},
    }

    def __init__(self, **kwargs):
        super(CelebritiesModel, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.confidence = kwargs.get('confidence', None)
        self.face_rectangle = kwargs.get('face_rectangle', None)
