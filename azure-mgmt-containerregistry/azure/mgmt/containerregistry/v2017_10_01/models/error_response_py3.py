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


class ErrorResponse(Model):
    """Azure container registry build API error object.

    :param error: Azure container registry build API error body.
    :type error: ~azure.mgmt.containerregistry.v2017_10_01.models.Error
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'Error'},
    }

    def __init__(self, *, error=None, **kwargs) -> None:
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = error
