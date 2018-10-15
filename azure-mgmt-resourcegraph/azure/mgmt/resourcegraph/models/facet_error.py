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

from .facet import Facet


class FacetError(Facet):
    """A facet whose execution resulted in an error.

    All required parameters must be populated in order to send to Azure.

    :param expression: Required. Facet expression, same as in the
     corresponding facet request.
    :type expression: str
    :param result_type: Required. Constant filled by server.
    :type result_type: str
    :param errors: Required. An array containing detected facet errors with
     details.
    :type errors: list[~azure.mgmt.resourcegraph.models.ErrorDetails]
    """

    _validation = {
        'expression': {'required': True},
        'result_type': {'required': True},
        'errors': {'required': True},
    }

    _attribute_map = {
        'expression': {'key': 'expression', 'type': 'str'},
        'result_type': {'key': 'resultType', 'type': 'str'},
        'errors': {'key': 'errors', 'type': '[ErrorDetails]'},
    }

    def __init__(self, **kwargs):
        super(FacetError, self).__init__(**kwargs)
        self.errors = kwargs.get('errors', None)
        self.result_type = 'FacetError'
