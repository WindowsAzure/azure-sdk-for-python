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


class X12ValidationOverride(Model):
    """The X12 validation override settings.

    :param message_id: The message id on which the validation settings has to
     be applied.
    :type message_id: str
    :param validate_edi_types: The value indicating whether to validate EDI
     types.
    :type validate_edi_types: bool
    :param validate_xsd_types: The value indicating whether to validate XSD
     types.
    :type validate_xsd_types: bool
    :param allow_leading_and_trailing_spaces_and_zeroes: The value indicating
     whether to allow leading and trailing spaces and zeroes.
    :type allow_leading_and_trailing_spaces_and_zeroes: bool
    :param validate_character_set: The value indicating whether to validate
     character Set.
    :type validate_character_set: bool
    :param trim_leading_and_trailing_spaces_and_zeroes: The value indicating
     whether to trim leading and trailing spaces and zeroes.
    :type trim_leading_and_trailing_spaces_and_zeroes: bool
    :param trailing_separator_policy: The trailing separator policy. Possible
     values include: 'NotSpecified', 'NotAllowed', 'Optional', 'Mandatory'
    :type trailing_separator_policy: str or :class:`TrailingSeparatorPolicy
     <azure.mgmt.logic.models.TrailingSeparatorPolicy>`
    """

    _validation = {
        'message_id': {'required': True},
        'validate_edi_types': {'required': True},
        'validate_xsd_types': {'required': True},
        'allow_leading_and_trailing_spaces_and_zeroes': {'required': True},
        'validate_character_set': {'required': True},
        'trim_leading_and_trailing_spaces_and_zeroes': {'required': True},
        'trailing_separator_policy': {'required': True},
    }

    _attribute_map = {
        'message_id': {'key': 'messageId', 'type': 'str'},
        'validate_edi_types': {'key': 'validateEdiTypes', 'type': 'bool'},
        'validate_xsd_types': {'key': 'validateXsdTypes', 'type': 'bool'},
        'allow_leading_and_trailing_spaces_and_zeroes': {'key': 'allowLeadingAndTrailingSpacesAndZeroes', 'type': 'bool'},
        'validate_character_set': {'key': 'validateCharacterSet', 'type': 'bool'},
        'trim_leading_and_trailing_spaces_and_zeroes': {'key': 'trimLeadingAndTrailingSpacesAndZeroes', 'type': 'bool'},
        'trailing_separator_policy': {'key': 'trailingSeparatorPolicy', 'type': 'TrailingSeparatorPolicy'},
    }

    def __init__(self, message_id, validate_edi_types, validate_xsd_types, allow_leading_and_trailing_spaces_and_zeroes, validate_character_set, trim_leading_and_trailing_spaces_and_zeroes, trailing_separator_policy):
        self.message_id = message_id
        self.validate_edi_types = validate_edi_types
        self.validate_xsd_types = validate_xsd_types
        self.allow_leading_and_trailing_spaces_and_zeroes = allow_leading_and_trailing_spaces_and_zeroes
        self.validate_character_set = validate_character_set
        self.trim_leading_and_trailing_spaces_and_zeroes = trim_leading_and_trailing_spaces_and_zeroes
        self.trailing_separator_policy = trailing_separator_policy
