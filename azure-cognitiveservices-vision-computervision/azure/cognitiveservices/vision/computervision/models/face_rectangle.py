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
    """An object describing face rectangle.

    :param left: X-coordinate of the top left point of the face.
    :type left: int
    :param top: Y-coordinate of the top left point of the face.
    :type top: int
    :param width: Width measured from the top-left point of the face.
    :type width: int
    :param height: Height measured from the top-left point of the face.
    :type height: int
    """

    _attribute_map = {
        'left': {'key': 'left', 'type': 'int'},
        'top': {'key': 'top', 'type': 'int'},
        'width': {'key': 'width', 'type': 'int'},
        'height': {'key': 'height', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(FaceRectangle, self).__init__(**kwargs)
        self.left = kwargs.get('left', None)
        self.top = kwargs.get('top', None)
        self.width = kwargs.get('width', None)
        self.height = kwargs.get('height', None)
