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


class FeedbackRecordsDTO(Model):
    """Active learning feedback records.

    :param feedback_records: List of feedback records.
    :type feedback_records:
     list[~azure.cognitiveservices.knowledge.qnamaker.authoring.models.FeedbackRecordDTO]
    """

    _attribute_map = {
        'feedback_records': {'key': 'feedbackRecords', 'type': '[FeedbackRecordDTO]'},
    }

    def __init__(self, **kwargs):
        super(FeedbackRecordsDTO, self).__init__(**kwargs)
        self.feedback_records = kwargs.get('feedback_records', None)
