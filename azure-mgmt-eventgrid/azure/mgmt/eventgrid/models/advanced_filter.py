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


class AdvancedFilter(Model):
    """Represents an advanced filter that can be used to filter events based on
    various event envelope/data fields.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: NumberInAdvancedFilter, NumberNotInAdvancedFilter,
    NumberLessThanAdvancedFilter, NumberGreaterThanAdvancedFilter,
    NumberLessThanOrEqualsAdvancedFilter,
    NumberGreaterThanOrEqualsAdvancedFilter, BoolEqualsAdvancedFilter,
    StringInAdvancedFilter, StringNotInAdvancedFilter,
    StringBeginsWithAdvancedFilter, StringEndsWithAdvancedFilter,
    StringContainsAdvancedFilter

    All required parameters must be populated in order to send to Azure.

    :param key: The filter key. Represents an event property with upto two
     levels of nesting.
    :type key: str
    :param operator_type: Required. Constant filled by server.
    :type operator_type: str
    """

    _validation = {
        'operator_type': {'required': True},
    }

    _attribute_map = {
        'key': {'key': 'key', 'type': 'str'},
        'operator_type': {'key': 'operatorType', 'type': 'str'},
    }

    _subtype_map = {
        'operator_type': {'NumberIn': 'NumberInAdvancedFilter', 'NumberNotIn': 'NumberNotInAdvancedFilter', 'NumberLessThan': 'NumberLessThanAdvancedFilter', 'NumberGreaterThan': 'NumberGreaterThanAdvancedFilter', 'NumberLessThanOrEquals': 'NumberLessThanOrEqualsAdvancedFilter', 'NumberGreaterThanOrEquals': 'NumberGreaterThanOrEqualsAdvancedFilter', 'BoolEquals': 'BoolEqualsAdvancedFilter', 'StringIn': 'StringInAdvancedFilter', 'StringNotIn': 'StringNotInAdvancedFilter', 'StringBeginsWith': 'StringBeginsWithAdvancedFilter', 'StringEndsWith': 'StringEndsWithAdvancedFilter', 'StringContains': 'StringContainsAdvancedFilter'}
    }

    def __init__(self, **kwargs):
        super(AdvancedFilter, self).__init__(**kwargs)
        self.key = kwargs.get('key', None)
        self.operator_type = None
