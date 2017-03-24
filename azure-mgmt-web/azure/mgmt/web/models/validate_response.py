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


class ValidateResponse(Model):
    """Describes the result of resource validation.

    :param status: Result of validation.
    :type status: str
    :param error: Error details for the case when validation fails.
    :type error: :class:`ValidateResponseError
     <azure.mgmt.web.models.ValidateResponseError>`
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'error': {'key': 'error', 'type': 'ValidateResponseError'},
    }

    def __init__(self, status=None, error=None):
        self.status = status
        self.error = error
