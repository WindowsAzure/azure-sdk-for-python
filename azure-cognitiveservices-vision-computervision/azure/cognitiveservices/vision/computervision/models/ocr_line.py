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


class OcrLine(Model):
    """An object describing a single recognized line of text.

    :param bounding_box: Bounding box of a recognized line. The four integers
     represent the x-coordinate of the left edge, the y-coordinate of the top
     edge, width, and height of the bounding box, in the coordinate system of
     the input image, after it has been rotated around its center according to
     the detected text angle (see textAngle property), with the origin at the
     top-left corner, and the y-axis pointing down.
    :type bounding_box: str
    :param words: An array of objects, where each object represents a
     recognized word.
    :type words:
     list[~azure.cognitiveservices.vision.computervision.models.OcrWord]
    """

    _attribute_map = {
        'bounding_box': {'key': 'boundingBox', 'type': 'str'},
        'words': {'key': 'words', 'type': '[OcrWord]'},
    }

    def __init__(self, bounding_box=None, words=None):
        super(OcrLine, self).__init__()
        self.bounding_box = bounding_box
        self.words = words
