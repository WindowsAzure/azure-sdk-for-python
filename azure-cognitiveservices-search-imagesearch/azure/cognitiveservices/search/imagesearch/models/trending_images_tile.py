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


class TrendingImagesTile(Model):
    """Defines an image tile.

    All required parameters must be populated in order to send to Azure.

    :param query: Required. A query that returns a Bing search results page
     with more images of the subject. For example, if the category is Popular
     People Searches, then the thumbnail is of a popular person. The query
     would return a Bing search results page with more images of that person.
    :type query: ~azure.cognitiveservices.search.imagesearch.models.Query
    :param image: Required. The image's thumbnail.
    :type image:
     ~azure.cognitiveservices.search.imagesearch.models.ImageObject
    """

    _validation = {
        'query': {'required': True},
        'image': {'required': True},
    }

    _attribute_map = {
        'query': {'key': 'query', 'type': 'Query'},
        'image': {'key': 'image', 'type': 'ImageObject'},
    }

    def __init__(self, **kwargs):
        super(TrendingImagesTile, self).__init__(**kwargs)
        self.query = kwargs.get('query', None)
        self.image = kwargs.get('image', None)
