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


class UsageName(Model):
    """The usage names.

    :param value: A string describing the resource name.
    :type value: str
    :param localized_value: A localized string describing the resource name.
    :type localized_value: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': 'str'},
        'localized_value': {'key': 'localizedValue', 'type': 'str'},
    }

    def __init__(self, value=None, localized_value=None):
        super(UsageName, self).__init__()
        self.value = value
        self.localized_value = localized_value
