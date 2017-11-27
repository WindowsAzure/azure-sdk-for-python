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


class PolybaseSettings(Model):
    """PolyBase settings.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param reject_type: Reject type. Possible values include: 'value',
     'percentage'
    :type reject_type: str or
     ~azure.mgmt.datafactory.models.PolybaseSettingsRejectType
    :param reject_value: Specifies the value or the percentage of rows that
     can be rejected before the query fails. Type: number (or Expression with
     resultType number), minimum: 0.
    :type reject_value: object
    :param reject_sample_value: Determines the number of rows to attempt to
     retrieve before the PolyBase recalculates the percentage of rejected rows.
     Type: integer (or Expression with resultType integer), minimum: 0.
    :type reject_sample_value: object
    :param use_type_default: Specifies how to handle missing values in
     delimited text files when PolyBase retrieves data from the text file.
     Type: boolean (or Expression with resultType boolean).
    :type use_type_default: object
    """

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'reject_type': {'key': 'rejectType', 'type': 'str'},
        'reject_value': {'key': 'rejectValue', 'type': 'object'},
        'reject_sample_value': {'key': 'rejectSampleValue', 'type': 'object'},
        'use_type_default': {'key': 'useTypeDefault', 'type': 'object'},
    }

    def __init__(self, additional_properties=None, reject_type=None, reject_value=None, reject_sample_value=None, use_type_default=None):
        self.additional_properties = additional_properties
        self.reject_type = reject_type
        self.reject_value = reject_value
        self.reject_sample_value = reject_sample_value
        self.use_type_default = use_type_default
