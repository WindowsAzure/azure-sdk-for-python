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


class InformationProtectionKeyword(Model):
    """The information type keyword.

    :param pattern: The keyword pattern.
    :type pattern: str
    :param custom: Indicates whether the keyword is custom or not.
    :type custom: bool
    :param can_be_numeric: Indicates whether the keyword can be applied on
     numeric types or not.
    :type can_be_numeric: bool
    :param excluded: Indicates whether the keyword is excluded or not.
    :type excluded: bool
    """

    _attribute_map = {
        'pattern': {'key': 'pattern', 'type': 'str'},
        'custom': {'key': 'custom', 'type': 'bool'},
        'can_be_numeric': {'key': 'canBeNumeric', 'type': 'bool'},
        'excluded': {'key': 'excluded', 'type': 'bool'},
    }

    def __init__(self, *, pattern: str=None, custom: bool=None, can_be_numeric: bool=None, excluded: bool=None, **kwargs) -> None:
        super(InformationProtectionKeyword, self).__init__(**kwargs)
        self.pattern = pattern
        self.custom = custom
        self.can_be_numeric = can_be_numeric
        self.excluded = excluded
