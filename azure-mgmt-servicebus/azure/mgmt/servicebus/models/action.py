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


class Action(Model):
    """Represents the filter actions which are allowed for the transformation of a
    message that have been matched by a filter expression.

    :param sql_expression: SQL expression. e.g. MyProperty='ABC'
    :type sql_expression: str
    :param compatibility_level: This property is reserved for future use. An
     integer value showing the compatibility level, currently hard-coded to 20.
    :type compatibility_level: int
    :param requires_preprocessing: Value that indicates whether the rule
     action requires preprocessing. Default value: True .
    :type requires_preprocessing: bool
    """

    _attribute_map = {
        'sql_expression': {'key': 'sqlExpression', 'type': 'str'},
        'compatibility_level': {'key': 'compatibilityLevel', 'type': 'int'},
        'requires_preprocessing': {'key': 'requiresPreprocessing', 'type': 'bool'},
    }

    def __init__(self, sql_expression=None, compatibility_level=None, requires_preprocessing=True):
        super(Action, self).__init__()
        self.sql_expression = sql_expression
        self.compatibility_level = compatibility_level
        self.requires_preprocessing = requires_preprocessing
