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


class Facet(Model):
    """A facet containing additional statistics on the response of a query. Can be
    either FacetResult or FacetError.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: FacetResult, FacetError

    All required parameters must be populated in order to send to Azure.

    :param expression: Required. Facet expression, same as in the
     corresponding facet request.
    :type expression: str
    :param result_type: Required. Constant filled by server.
    :type result_type: str
    """

    _validation = {
        'expression': {'required': True},
        'result_type': {'required': True},
    }

    _attribute_map = {
        'expression': {'key': 'expression', 'type': 'str'},
        'result_type': {'key': 'resultType', 'type': 'str'},
    }

    _subtype_map = {
        'result_type': {'FacetResult': 'FacetResult', 'FacetError': 'FacetError'}
    }

    def __init__(self, **kwargs):
        super(Facet, self).__init__(**kwargs)
        self.expression = kwargs.get('expression', None)
        self.result_type = None
