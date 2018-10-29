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


class IdentifyCandidate(Model):
    """All possible faces that may qualify.

    All required parameters must be populated in order to send to Azure.

    :param person_id: Required. Id of candidate
    :type person_id: str
    :param confidence: Required. Confidence threshold of identification, used
     to judge whether one face belong to one person. The range of
     confidenceThreshold is [0, 1] (default specified by algorithm).
    :type confidence: float
    """

    _validation = {
        'person_id': {'required': True},
        'confidence': {'required': True},
    }

    _attribute_map = {
        'person_id': {'key': 'personId', 'type': 'str'},
        'confidence': {'key': 'confidence', 'type': 'float'},
    }

    def __init__(self, *, person_id: str, confidence: float, **kwargs) -> None:
        super(IdentifyCandidate, self).__init__(**kwargs)
        self.person_id = person_id
        self.confidence = confidence
