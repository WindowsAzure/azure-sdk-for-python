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
from msrest.exceptions import HttpOperationError


class QueryFailure(Model):
    """Error response.

    :param error: Error definition.
    :type error: ~azure.mgmt.policyinsights.models.QueryFailureError
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'QueryFailureError'},
    }

    def __init__(self, error=None):
        super(QueryFailure, self).__init__()
        self.error = error


class QueryFailureException(HttpOperationError):
    """Server responsed with exception of type: 'QueryFailure'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(QueryFailureException, self).__init__(deserialize, response, 'QueryFailure', *args)
