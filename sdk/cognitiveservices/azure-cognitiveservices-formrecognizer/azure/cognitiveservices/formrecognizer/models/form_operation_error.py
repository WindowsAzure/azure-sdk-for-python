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


class FormOperationError(Model):
    """Error reported during an operation.

    All required parameters must be populated in order to send to Azure.

    :param error_message: Required. Message reported during the train
     operation.
    :type error_message: str
    """

    _validation = {
        'error_message': {'required': True},
    }

    _attribute_map = {
        'error_message': {'key': 'errorMessage', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(FormOperationError, self).__init__(**kwargs)
        self.error_message = kwargs.get('error_message', None)
