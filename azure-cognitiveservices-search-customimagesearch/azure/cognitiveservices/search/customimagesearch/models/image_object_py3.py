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

from .media_object import MediaObject


class ImageObject(MediaObject):
    """Defines an image.

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
    :ivar name: The name of the thing represented by this object.
    :vartype name: str
    :ivar url: The URL to get more information about the thing represented by
     this object.
    :vartype url: str
    :ivar image: An image of the item.
    :vartype image:
     ~azure.cognitiveservices.search.customimagesearch.models.ImageObject
    :ivar description: A short description of the item.
    :vartype description: str
    :ivar alternate_name: An alias for the item
    :vartype alternate_name: str
    :ivar bing_id: An ID that uniquely identifies this item.
    :vartype bing_id: str
    :ivar thumbnail_url: The URL to a thumbnail of the item.
    :vartype thumbnail_url: str
    :ivar provider: The source of the creative work.
    :vartype provider:
     list[~azure.cognitiveservices.search.customimagesearch.models.Thing]
    :ivar text: Text content of this creative work
    :vartype text: str
    :ivar content_url: Original URL to retrieve the source (file) for the
     media object (e.g the source URL for the image).
    :vartype content_url: str
    :ivar host_page_url: URL of the page that hosts the media object.
    :vartype host_page_url: str
    :ivar content_size: Size of the media object content (use format "value
     unit" e.g "1024 B").
    :vartype content_size: str
    :ivar encoding_format: Encoding format (e.g mp3, mp4, jpeg, etc).
    :vartype encoding_format: str
    :ivar host_page_display_url: Display URL of the page that hosts the media
     object.
    :vartype host_page_display_url: str
    :ivar width: The width of the media object, in pixels.
    :vartype width: int
    :ivar height: The height of the media object, in pixels.
    :vartype height: int
    :ivar thumbnail: The URL to a thumbnail of the image
    :vartype thumbnail:
     ~azure.cognitiveservices.search.customimagesearch.models.ImageObject
    :ivar image_insights_token: The token that you use in a subsequent call to
     the Image Search API to get additional information about the image. For
     information about using this token, see the insightsToken query parameter.
    :vartype image_insights_token: str
    :ivar image_id: Unique Id for the image
    :vartype image_id: str
    :ivar accent_color: A three-byte hexadecimal number that represents the
     color that dominates the image. Use the color as the temporary background
     in your client until the image is loaded.
    :vartype accent_color: str
    :ivar visual_words: Visual representation of the image. Used for getting
     more sizes
    :vartype visual_words: str
    """

    _validation = {
        '_type': {'required': True},
        'id': {'readonly': True},
        'read_link': {'readonly': True},
        'web_search_url': {'readonly': True},
        'name': {'readonly': True},
        'url': {'readonly': True},
        'image': {'readonly': True},
        'description': {'readonly': True},
        'alternate_name': {'readonly': True},
        'bing_id': {'readonly': True},
        'thumbnail_url': {'readonly': True},
        'provider': {'readonly': True},
        'text': {'readonly': True},
        'content_url': {'readonly': True},
        'host_page_url': {'readonly': True},
        'content_size': {'readonly': True},
        'encoding_format': {'readonly': True},
        'host_page_display_url': {'readonly': True},
        'width': {'readonly': True},
        'height': {'readonly': True},
        'thumbnail': {'readonly': True},
        'image_insights_token': {'readonly': True},
        'image_id': {'readonly': True},
        'accent_color': {'readonly': True},
        'visual_words': {'readonly': True},
    }

    _attribute_map = {
        '_type': {'key': '_type', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'read_link': {'key': 'readLink', 'type': 'str'},
        'web_search_url': {'key': 'webSearchUrl', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'image': {'key': 'image', 'type': 'ImageObject'},
        'description': {'key': 'description', 'type': 'str'},
        'alternate_name': {'key': 'alternateName', 'type': 'str'},
        'bing_id': {'key': 'bingId', 'type': 'str'},
        'thumbnail_url': {'key': 'thumbnailUrl', 'type': 'str'},
        'provider': {'key': 'provider', 'type': '[Thing]'},
        'text': {'key': 'text', 'type': 'str'},
        'content_url': {'key': 'contentUrl', 'type': 'str'},
        'host_page_url': {'key': 'hostPageUrl', 'type': 'str'},
        'content_size': {'key': 'contentSize', 'type': 'str'},
        'encoding_format': {'key': 'encodingFormat', 'type': 'str'},
        'host_page_display_url': {'key': 'hostPageDisplayUrl', 'type': 'str'},
        'width': {'key': 'width', 'type': 'int'},
        'height': {'key': 'height', 'type': 'int'},
        'thumbnail': {'key': 'thumbnail', 'type': 'ImageObject'},
        'image_insights_token': {'key': 'imageInsightsToken', 'type': 'str'},
        'image_id': {'key': 'imageId', 'type': 'str'},
        'accent_color': {'key': 'accentColor', 'type': 'str'},
        'visual_words': {'key': 'visualWords', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(ImageObject, self).__init__(**kwargs)
        self.thumbnail = None
        self.image_insights_token = None
        self.image_id = None
        self.accent_color = None
        self.visual_words = None
        self._type = 'ImageObject'
