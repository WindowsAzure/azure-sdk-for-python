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


class TextRecognitionResult(Model):
    """Json object representing a recognized text region.

    All required parameters must be populated in order to send to Azure.

    :param page: The 1-based page number of the recognition result.
    :type page: int
    :param clockwise_orientation: The orientation of the image in degrees in
     the clockwise direction. Range between [0, 360).
    :type clockwise_orientation: float
    :param width: The width of the image in pixels or the PDF in inches.
    :type width: float
    :param height: The height of the image in pixels or the PDF in inches.
    :type height: float
    :param unit: The unit used in the Width, Height and BoundingBox. For
     images, the unit is "pixel". For PDF, the unit is "inch". Possible values
     include: 'pixel', 'inch'
    :type unit: str or
     ~azure.cognitiveservices.vision.computervision.models.TextRecognitionResultDimensionUnit
    :param lines: Required. A list of recognized text lines.
    :type lines:
     list[~azure.cognitiveservices.vision.computervision.models.Line]
    """

    _validation = {
        'lines': {'required': True},
    }

    _attribute_map = {
        'page': {'key': 'page', 'type': 'int'},
        'clockwise_orientation': {'key': 'clockwiseOrientation', 'type': 'float'},
        'width': {'key': 'width', 'type': 'float'},
        'height': {'key': 'height', 'type': 'float'},
        'unit': {'key': 'unit', 'type': 'TextRecognitionResultDimensionUnit'},
        'lines': {'key': 'lines', 'type': '[Line]'},
    }

    def __init__(self, *, lines, page: int=None, clockwise_orientation: float=None, width: float=None, height: float=None, unit=None, **kwargs) -> None:
        super(TextRecognitionResult, self).__init__(**kwargs)
        self.page = page
        self.clockwise_orientation = clockwise_orientation
        self.width = width
        self.height = height
        self.unit = unit
        self.lines = lines
