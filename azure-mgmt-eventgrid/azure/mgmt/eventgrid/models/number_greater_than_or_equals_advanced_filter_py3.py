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

from .advanced_filter_py3 import AdvancedFilter


class NumberGreaterThanOrEqualsAdvancedFilter(AdvancedFilter):
    """NumberGreaterThanOrEquals Filter.

    All required parameters must be populated in order to send to Azure.

    :param key: The filter key. Represents an event property with upto two
     levels of nesting.
    :type key: str
    :param operator_type: Required. Constant filled by server.
    :type operator_type: str
    :param value: The filter value
    :type value: float
    """

    _validation = {
        'operator_type': {'required': True},
    }

    _attribute_map = {
        'key': {'key': 'key', 'type': 'str'},
        'operator_type': {'key': 'operatorType', 'type': 'str'},
        'value': {'key': 'value', 'type': 'float'},
    }

    def __init__(self, *, key: str=None, value: float=None, **kwargs) -> None:
        super(NumberGreaterThanOrEqualsAdvancedFilter, self).__init__(key=key, **kwargs)
        self.value = value
        self.operator_type = 'NumberGreaterThanOrEquals'
