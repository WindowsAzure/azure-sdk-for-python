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


class VerifyResult(Model):
    """Result of the verify operation.

    All required parameters must be populated in order to send to Azure.

    :param is_identical: Required. True if the two faces belong to the same
     person or the face belongs to the person, otherwise false.
    :type is_identical: bool
    :param confidence: Required. A number indicates the similarity confidence
     of whether two faces belong to the same person, or whether the face
     belongs to the person. By default, isIdentical is set to True if
     similarity confidence is greater than or equal to 0.5. This is useful for
     advanced users to override "isIdentical" and fine-tune the result on their
     own data.
    :type confidence: float
    """

    _validation = {
        'is_identical': {'required': True},
        'confidence': {'required': True},
    }

    _attribute_map = {
        'is_identical': {'key': 'isIdentical', 'type': 'bool'},
        'confidence': {'key': 'confidence', 'type': 'float'},
    }

    def __init__(self, *, is_identical: bool, confidence: float, **kwargs) -> None:
        super(VerifyResult, self).__init__(**kwargs)
        self.is_identical = is_identical
        self.confidence = confidence
