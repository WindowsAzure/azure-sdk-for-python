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


class BatchLabelExample(Model):
    """Response when adding a batch of labeled example utterances.

    :param value:
    :type value:
     ~azure.cognitiveservices.language.luis.authoring.models.LabelExampleResponse
    :param has_error:
    :type has_error: bool
    :param error:
    :type error:
     ~azure.cognitiveservices.language.luis.authoring.models.OperationStatus
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': 'LabelExampleResponse'},
        'has_error': {'key': 'hasError', 'type': 'bool'},
        'error': {'key': 'error', 'type': 'OperationStatus'},
    }

    def __init__(self, *, value=None, has_error: bool=None, error=None, **kwargs) -> None:
        super(BatchLabelExample, self).__init__(**kwargs)
        self.value = value
        self.has_error = has_error
        self.error = error
