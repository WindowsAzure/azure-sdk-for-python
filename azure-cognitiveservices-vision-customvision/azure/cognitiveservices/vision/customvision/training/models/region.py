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


class Region(Model):
    """Region.

    All required parameters must be populated in order to send to Azure.

    :param tag_id: Required. Id of the tag associated with this region.
    :type tag_id: str
    :param left: Required. Coordinate of the left boundary.
    :type left: float
    :param top: Required. Coordinate of the top boundary.
    :type top: float
    :param width: Required. Width.
    :type width: float
    :param height: Required. Height.
    :type height: float
    """

    _validation = {
        'tag_id': {'required': True},
        'left': {'required': True},
        'top': {'required': True},
        'width': {'required': True},
        'height': {'required': True},
    }

    _attribute_map = {
        'tag_id': {'key': 'tagId', 'type': 'str'},
        'left': {'key': 'left', 'type': 'float'},
        'top': {'key': 'top', 'type': 'float'},
        'width': {'key': 'width', 'type': 'float'},
        'height': {'key': 'height', 'type': 'float'},
    }

    def __init__(self, **kwargs):
        super(Region, self).__init__(**kwargs)
        self.tag_id = kwargs.get('tag_id', None)
        self.left = kwargs.get('left', None)
        self.top = kwargs.get('top', None)
        self.width = kwargs.get('width', None)
        self.height = kwargs.get('height', None)
