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


class FaceRectangle(Model):
    """A rectangle within which a face can be found.

    All required parameters must be populated in order to send to Azure.

    :param width: Required. The width of the rectangle, in pixels.
    :type width: int
    :param height: Required. The height of the rectangle, in pixels.
    :type height: int
    :param left: Required. The distance from the left edge if the image to the
     left edge of the rectangle, in pixels.
    :type left: int
    :param top: Required. The distance from the top edge if the image to the
     top edge of the rectangle, in pixels.
    :type top: int
    """

    _validation = {
        'width': {'required': True},
        'height': {'required': True},
        'left': {'required': True},
        'top': {'required': True},
    }

    _attribute_map = {
        'width': {'key': 'width', 'type': 'int'},
        'height': {'key': 'height', 'type': 'int'},
        'left': {'key': 'left', 'type': 'int'},
        'top': {'key': 'top', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(FaceRectangle, self).__init__(**kwargs)
        self.width = kwargs.get('width', None)
        self.height = kwargs.get('height', None)
        self.left = kwargs.get('left', None)
        self.top = kwargs.get('top', None)
