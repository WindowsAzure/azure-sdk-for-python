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


class ImageCaption(Model):
    """An image caption, i.e. a brief description of what the image depicts.

    :param text: The text of the caption
    :type text: str
    :param confidence: The level of confidence the service has in the caption
    :type confidence: float
    """

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'confidence': {'key': 'confidence', 'type': 'float'},
    }

    def __init__(self, *, text: str=None, confidence: float=None, **kwargs) -> None:
        super(ImageCaption, self).__init__(**kwargs)
        self.text = text
        self.confidence = confidence
