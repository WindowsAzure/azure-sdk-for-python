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

from .advanced_filter import AdvancedFilter


class NumberLessThanOrEqualsAdvancedFilter(AdvancedFilter):
    """NumberLessThanOrEquals Advanced Filter.

    All required parameters must be populated in order to send to Azure.

    :param key: The field/property in the event based on which you want to
     filter.
    :type key: str
    :param operator_type: Required. Constant filled by server.
    :type operator_type: str
    :param value: The filter value.
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

    def __init__(self, **kwargs):
        super(NumberLessThanOrEqualsAdvancedFilter, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.operator_type = 'NumberLessThanOrEquals'
