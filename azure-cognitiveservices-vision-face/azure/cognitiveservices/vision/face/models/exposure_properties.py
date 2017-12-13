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


class ExposureProperties(Model):
    """Properties describing exposure level of the image.

    :param exposure_level: An enum value indicating level of exposure.
     Possible values include: 'UnderExposure', 'GoodExposure', 'OverExposure'
    :type exposure_level: str or
     ~azure.cognitiveservices.vision.face.models.ExposureLevels
    :param value: A number indicating level of exposure level ranging from 0
     to 1. [0, 0.25) is under exposure. [0.25, 0.75) is good exposure. [0.75,
     1] is over exposure.
    :type value: float
    """

    _validation = {
        'value': {'maximum': 1, 'minimum': 0},
    }

    _attribute_map = {
        'exposure_level': {'key': 'exposureLevel', 'type': 'ExposureLevels'},
        'value': {'key': 'value', 'type': 'float'},
    }

    def __init__(self, exposure_level=None, value=None):
        self.exposure_level = exposure_level
        self.value = value
