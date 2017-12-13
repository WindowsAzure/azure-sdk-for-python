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


class FoundFaces(Model):
    """Request object the contains found faces.

    :param status: The evaluate status
    :type status:
     ~azure.cognitiveservices.vision.contentmoderator.models.Status
    :param tracking_id: The tracking id.
    :type tracking_id: str
    :param cache_id: The cache id.
    :type cache_id: str
    :param result: True if result was found.
    :type result: bool
    :param count: Number of faces found.
    :type count: int
    :param advanced_info: The advanced info.
    :type advanced_info:
     list[~azure.cognitiveservices.vision.contentmoderator.models.KeyValuePair]
    :param faces: The list of faces.
    :type faces:
     list[~azure.cognitiveservices.vision.contentmoderator.models.Face]
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'Status'},
        'tracking_id': {'key': 'trackingId', 'type': 'str'},
        'cache_id': {'key': 'cacheId', 'type': 'str'},
        'result': {'key': 'result', 'type': 'bool'},
        'count': {'key': 'count', 'type': 'int'},
        'advanced_info': {'key': 'advancedInfo', 'type': '[KeyValuePair]'},
        'faces': {'key': 'faces', 'type': '[Face]'},
    }

    def __init__(self, status=None, tracking_id=None, cache_id=None, result=None, count=None, advanced_info=None, faces=None):
        self.status = status
        self.tracking_id = tracking_id
        self.cache_id = cache_id
        self.result = result
        self.count = count
        self.advanced_info = advanced_info
        self.faces = faces
