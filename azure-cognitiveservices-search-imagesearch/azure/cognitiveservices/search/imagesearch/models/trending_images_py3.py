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

from .response_py3 import Response


class TrendingImages(Response):
    """The top-level object that the response includes when a trending images
    request succeeds.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param _type: Required. Constant filled by server.
    :type _type: str
    :ivar id: A String identifier.
    :vartype id: str
    :ivar read_link: The URL that returns this resource.
    :vartype read_link: str
    :ivar web_search_url: The URL To Bing's search result for this item.
    :vartype web_search_url: str
    :param categories: Required. A list that identifies categories of images
     and a list of trending images in that category.
    :type categories:
     list[~azure.cognitiveservices.search.imagesearch.models.TrendingImagesCategory]
    """

    _validation = {
        '_type': {'required': True},
        'id': {'readonly': True},
        'read_link': {'readonly': True},
        'web_search_url': {'readonly': True},
        'categories': {'required': True},
    }

    _attribute_map = {
        '_type': {'key': '_type', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'read_link': {'key': 'readLink', 'type': 'str'},
        'web_search_url': {'key': 'webSearchUrl', 'type': 'str'},
        'categories': {'key': 'categories', 'type': '[TrendingImagesCategory]'},
    }

    def __init__(self, *, categories, **kwargs) -> None:
        super(TrendingImages, self).__init__(**kwargs)
        self.categories = categories
        self._type = 'TrendingImages'
