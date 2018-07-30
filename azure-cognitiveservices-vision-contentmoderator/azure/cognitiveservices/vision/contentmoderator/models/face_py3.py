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


class Face(Model):
    """Coordinates to the found face.

    :param bottom: The bottom coordinate.
    :type bottom: int
    :param left: The left coordinate.
    :type left: int
    :param right: The right coordinate.
    :type right: int
    :param top: The top coordinate.
    :type top: int
    """

    _attribute_map = {
        'bottom': {'key': 'Bottom', 'type': 'int'},
        'left': {'key': 'Left', 'type': 'int'},
        'right': {'key': 'Right', 'type': 'int'},
        'top': {'key': 'Top', 'type': 'int'},
    }

    def __init__(self, *, bottom: int=None, left: int=None, right: int=None, top: int=None, **kwargs) -> None:
        super(Face, self).__init__(**kwargs)
        self.bottom = bottom
        self.left = left
        self.right = right
        self.top = top
