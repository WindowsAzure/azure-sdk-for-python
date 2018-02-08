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


class ClassificationCategory3(Model):
    """The category3 score details of the text. <a
    href="https://aka.ms/textClassifyCategories">Click here</a> for more
    details on category classification.

    :param score: The category3 score.
    :type score: float
    """

    _attribute_map = {
        'score': {'key': 'Score', 'type': 'float'},
    }

    def __init__(self, score=None):
        super(ClassificationCategory3, self).__init__()
        self.score = score
