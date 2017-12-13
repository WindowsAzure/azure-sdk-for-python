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


class CreateVideoReviewsBodyItem(Model):
    """Schema items of the body.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param video_frames: Optional metadata details.
    :type video_frames:
     list[~azure.cognitiveservices.contentmoderator.models.CreateVideoReviewsBodyItemVideoFramesItem]
    :param metadata: Optional metadata details.
    :type metadata:
     list[~azure.cognitiveservices.contentmoderator.models.CreateVideoReviewsBodyItemMetadataItem]
    :ivar type: Type of the content. Default value: "Video" .
    :vartype type: str
    :param content: Video content url to review.
    :type content: str
    :param content_id: Content Identifier.
    :type content_id: str
    :param status: Status of the video(Complete,Unpublished,Pending). Possible
     values include: 'Complete', 'Unpublished', 'Pending'
    :type status: str or ~azure.cognitiveservices.contentmoderator.models.enum
    :param timescale: Timescale of the video.
    :type timescale: int
    :param callback_endpoint: Optional CallbackEndpoint.
    :type callback_endpoint: str
    """

    _validation = {
        'type': {'required': True, 'constant': True},
        'content': {'required': True},
        'content_id': {'required': True},
        'status': {'required': True},
    }

    _attribute_map = {
        'video_frames': {'key': 'VideoFrames', 'type': '[CreateVideoReviewsBodyItemVideoFramesItem]'},
        'metadata': {'key': 'Metadata', 'type': '[CreateVideoReviewsBodyItemMetadataItem]'},
        'type': {'key': 'Type', 'type': 'str'},
        'content': {'key': 'Content', 'type': 'str'},
        'content_id': {'key': 'ContentId', 'type': 'str'},
        'status': {'key': 'Status', 'type': 'str'},
        'timescale': {'key': 'Timescale', 'type': 'int'},
        'callback_endpoint': {'key': 'CallbackEndpoint', 'type': 'str'},
    }

    type = "Video"

    def __init__(self, content, content_id, status, video_frames=None, metadata=None, timescale=None, callback_endpoint=None):
        self.video_frames = video_frames
        self.metadata = metadata
        self.content = content
        self.content_id = content_id
        self.status = status
        self.timescale = timescale
        self.callback_endpoint = callback_endpoint
