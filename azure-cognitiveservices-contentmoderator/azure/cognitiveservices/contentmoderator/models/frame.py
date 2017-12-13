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


class Frame(Model):
    """Video frame property details.

    :param timestamp: Timestamp of the frame.
    :type timestamp: str
    :param frame_image: Frame image.
    :type frame_image: str
    :param metadata: Array of KeyValue.
    :type metadata:
     list[~azure.cognitiveservices.contentmoderator.models.KeyValuePair]
    :param reviewer_result_tags: Reviewer result tags.
    :type reviewer_result_tags:
     list[~azure.cognitiveservices.contentmoderator.models.Tag]
    """

    _attribute_map = {
        'timestamp': {'key': 'timestamp', 'type': 'str'},
        'frame_image': {'key': 'frameImage', 'type': 'str'},
        'metadata': {'key': 'metadata', 'type': '[KeyValuePair]'},
        'reviewer_result_tags': {'key': 'reviewerResultTags', 'type': '[Tag]'},
    }

    def __init__(self, timestamp=None, frame_image=None, metadata=None, reviewer_result_tags=None):
        self.timestamp = timestamp
        self.frame_image = frame_image
        self.metadata = metadata
        self.reviewer_result_tags = reviewer_result_tags
