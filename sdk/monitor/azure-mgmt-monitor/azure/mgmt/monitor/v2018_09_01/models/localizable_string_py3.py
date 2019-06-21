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


class LocalizableString(Model):
    """The localizable string class.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. The invariant value.
    :type value: str
    :param localized_value: The locale specific value.
    :type localized_value: str
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': 'str'},
        'localized_value': {'key': 'localizedValue', 'type': 'str'},
    }

    def __init__(self, *, value: str, localized_value: str=None, **kwargs) -> None:
        super(LocalizableString, self).__init__(**kwargs)
        self.value = value
        self.localized_value = localized_value
