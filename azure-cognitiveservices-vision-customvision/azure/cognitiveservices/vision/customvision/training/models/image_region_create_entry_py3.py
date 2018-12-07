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


class ImageRegionCreateEntry(Model):
    """Entry associating a region to an image.

    :param image_id: Id of the image.
    :type image_id: str
    :param tag_id: Id of the tag associated with this region.
    :type tag_id: str
    :param left:
    :type left: float
    :param top:
    :type top: float
    :param width:
    :type width: float
    :param height:
    :type height: float
    """

    _attribute_map = {
        'image_id': {'key': 'imageId', 'type': 'str'},
        'tag_id': {'key': 'tagId', 'type': 'str'},
        'left': {'key': 'left', 'type': 'float'},
        'top': {'key': 'top', 'type': 'float'},
        'width': {'key': 'width', 'type': 'float'},
        'height': {'key': 'height', 'type': 'float'},
    }

    def __init__(self, *, image_id: str=None, tag_id: str=None, left: float=None, top: float=None, width: float=None, height: float=None, **kwargs) -> None:
        super(ImageRegionCreateEntry, self).__init__(**kwargs)
        self.image_id = image_id
        self.tag_id = tag_id
        self.left = left
        self.top = top
        self.width = width
        self.height = height
