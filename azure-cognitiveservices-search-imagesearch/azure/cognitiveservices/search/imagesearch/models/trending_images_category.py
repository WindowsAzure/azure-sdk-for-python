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


class TrendingImagesCategory(Model):
    """Defines the category of trending images.

    All required parameters must be populated in order to send to Azure.

    :param title: Required. The name of the image category. For example,
     Popular People Searches.
    :type title: str
    :param tiles: Required. A list of images that are trending in the
     category. Each tile contains an image and a URL that returns more images
     of the subject. For example, if the category is Popular People Searches,
     the image is of a popular person and the URL would return more images of
     that person.
    :type tiles:
     list[~azure.cognitiveservices.search.imagesearch.models.TrendingImagesTile]
    """

    _validation = {
        'title': {'required': True},
        'tiles': {'required': True},
    }

    _attribute_map = {
        'title': {'key': 'title', 'type': 'str'},
        'tiles': {'key': 'tiles', 'type': '[TrendingImagesTile]'},
    }

    def __init__(self, **kwargs):
        super(TrendingImagesCategory, self).__init__(**kwargs)
        self.title = kwargs.get('title', None)
        self.tiles = kwargs.get('tiles', None)
