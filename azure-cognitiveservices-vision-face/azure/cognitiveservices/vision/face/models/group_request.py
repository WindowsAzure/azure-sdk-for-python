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


class GroupRequest(Model):
    """Request body for group request.

    :param face_ids: Array of candidate faceId created by Face - Detect. The
     maximum is 1000 faces
    :type face_ids: list[str]
    """

    _validation = {
        'face_ids': {'required': True, 'max_items': 1000},
    }

    _attribute_map = {
        'face_ids': {'key': 'faceIds', 'type': '[str]'},
    }

    def __init__(self, face_ids):
        super(GroupRequest, self).__init__()
        self.face_ids = face_ids
