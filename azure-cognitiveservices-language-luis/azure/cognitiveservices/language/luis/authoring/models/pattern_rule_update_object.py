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


class PatternRuleUpdateObject(Model):
    """Object model for updating a pattern.

    :param id: The pattern ID.
    :type id: str
    :param pattern: The pattern text.
    :type pattern: str
    :param intent: The intent's name which the pattern belongs to.
    :type intent: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'pattern': {'key': 'pattern', 'type': 'str'},
        'intent': {'key': 'intent', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PatternRuleUpdateObject, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.pattern = kwargs.get('pattern', None)
        self.intent = kwargs.get('intent', None)
