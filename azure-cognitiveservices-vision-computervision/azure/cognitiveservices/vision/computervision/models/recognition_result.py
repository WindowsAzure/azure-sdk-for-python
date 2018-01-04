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


class RecognitionResult(Model):
    """RecognitionResult.

    :param lines:
    :type lines:
     list[~azure.cognitiveservices.vision.computervision.models.Line]
    """

    _attribute_map = {
        'lines': {'key': 'lines', 'type': '[Line]'},
    }

    def __init__(self, lines=None):
        super(RecognitionResult, self).__init__()
        self.lines = lines
