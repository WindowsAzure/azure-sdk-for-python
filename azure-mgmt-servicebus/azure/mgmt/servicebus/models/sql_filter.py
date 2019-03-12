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


class SqlFilter(Model):
    """Represents a filter which is a composition of an expression and an action
    that is executed in the pub/sub pipeline.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param sql_expression: The SQL expression. e.g. MyProperty='ABC'
    :type sql_expression: str
    :ivar compatibility_level: This property is reserved for future use. An
     integer value showing the compatibility level, currently hard-coded to 20.
     Default value: 20 .
    :vartype compatibility_level: int
    :param requires_preprocessing: Value that indicates whether the rule
     action requires preprocessing. Default value: True .
    :type requires_preprocessing: bool
    """

    _validation = {
        'compatibility_level': {'readonly': True},
    }

    _attribute_map = {
        'sql_expression': {'key': 'sqlExpression', 'type': 'str'},
        'compatibility_level': {'key': 'compatibilityLevel', 'type': 'int'},
        'requires_preprocessing': {'key': 'requiresPreprocessing', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(SqlFilter, self).__init__(**kwargs)
        self.sql_expression = kwargs.get('sql_expression', None)
        self.compatibility_level = None
        self.requires_preprocessing = kwargs.get('requires_preprocessing', True)
