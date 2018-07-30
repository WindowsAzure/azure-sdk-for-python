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


class CreateVideoReviewsBodyItemVideoFramesItem(Model):
    """CreateVideoReviewsBodyItemVideoFramesItem.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Id of the frame.
    :type id: str
    :param timestamp: Required. Timestamp of the frame.
    :type timestamp: int
    :param frame_image: Required. Frame image Url.
    :type frame_image: str
    :param reviewer_result_tags:
    :type reviewer_result_tags:
     list[~azure.cognitiveservices.vision.contentmoderator.models.CreateVideoReviewsBodyItemVideoFramesItemReviewerResultTagsItem]
    :param metadata: Optional metadata details.
    :type metadata:
     list[~azure.cognitiveservices.vision.contentmoderator.models.CreateVideoReviewsBodyItemVideoFramesItemMetadataItem]
    """

    _validation = {
        'id': {'required': True},
        'timestamp': {'required': True},
        'frame_image': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'Id', 'type': 'str'},
        'timestamp': {'key': 'Timestamp', 'type': 'int'},
        'frame_image': {'key': 'FrameImage', 'type': 'str'},
        'reviewer_result_tags': {'key': 'ReviewerResultTags', 'type': '[CreateVideoReviewsBodyItemVideoFramesItemReviewerResultTagsItem]'},
        'metadata': {'key': 'Metadata', 'type': '[CreateVideoReviewsBodyItemVideoFramesItemMetadataItem]'},
    }

    def __init__(self, *, id: str, timestamp: int, frame_image: str, reviewer_result_tags=None, metadata=None, **kwargs) -> None:
        super(CreateVideoReviewsBodyItemVideoFramesItem, self).__init__(**kwargs)
        self.id = id
        self.timestamp = timestamp
        self.frame_image = frame_image
        self.reviewer_result_tags = reviewer_result_tags
        self.metadata = metadata
