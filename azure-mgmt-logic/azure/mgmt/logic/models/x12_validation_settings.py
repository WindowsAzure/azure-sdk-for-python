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


class X12ValidationSettings(Model):
    """X12ValidationSettings.

    :param validate_character_set: The value indicating whether to validate
     character set in the message.
    :type validate_character_set: bool
    :param check_duplicate_interchange_control_number: The value indicating
     whether to check for duplicate interchange control number.
    :type check_duplicate_interchange_control_number: bool
    :param interchange_control_number_validity_days: The validity period of
     interchange control number.
    :type interchange_control_number_validity_days: int
    :param check_duplicate_group_control_number: The value indicating whether
     to check for duplicate group control number.
    :type check_duplicate_group_control_number: bool
    :param check_duplicate_transaction_set_control_number: The value
     indicating whether to check for duplicate transaction set control number.
    :type check_duplicate_transaction_set_control_number: bool
    :param validate_edi_types: The value indicating whether to Whether to
     validate EDI types.
    :type validate_edi_types: bool
    :param validate_xsd_types: The value indicating whether to Whether to
     validate XSD types.
    :type validate_xsd_types: bool
    :param allow_leading_and_trailing_spaces_and_zeroes: The value indicating
     whether to allow leading and trailing spaces and zeroes.
    :type allow_leading_and_trailing_spaces_and_zeroes: bool
    :param trim_leading_and_trailing_spaces_and_zeroes: The value indicating
     whether to trim leading and trailing spaces and zeroes.
    :type trim_leading_and_trailing_spaces_and_zeroes: bool
    :param trailing_separator_policy: The trailing separator policy. Possible
     values include: 'NotSpecified', 'NotAllowed', 'Optional', 'Mandatory'
    :type trailing_separator_policy: str or :class:`TrailingSeparatorPolicy
     <azure.mgmt.logic.models.TrailingSeparatorPolicy>`
    """

    _attribute_map = {
        'validate_character_set': {'key': 'validateCharacterSet', 'type': 'bool'},
        'check_duplicate_interchange_control_number': {'key': 'checkDuplicateInterchangeControlNumber', 'type': 'bool'},
        'interchange_control_number_validity_days': {'key': 'interchangeControlNumberValidityDays', 'type': 'int'},
        'check_duplicate_group_control_number': {'key': 'checkDuplicateGroupControlNumber', 'type': 'bool'},
        'check_duplicate_transaction_set_control_number': {'key': 'checkDuplicateTransactionSetControlNumber', 'type': 'bool'},
        'validate_edi_types': {'key': 'validateEDITypes', 'type': 'bool'},
        'validate_xsd_types': {'key': 'validateXSDTypes', 'type': 'bool'},
        'allow_leading_and_trailing_spaces_and_zeroes': {'key': 'allowLeadingAndTrailingSpacesAndZeroes', 'type': 'bool'},
        'trim_leading_and_trailing_spaces_and_zeroes': {'key': 'trimLeadingAndTrailingSpacesAndZeroes', 'type': 'bool'},
        'trailing_separator_policy': {'key': 'trailingSeparatorPolicy', 'type': 'TrailingSeparatorPolicy'},
    }

    def __init__(self, validate_character_set=None, check_duplicate_interchange_control_number=None, interchange_control_number_validity_days=None, check_duplicate_group_control_number=None, check_duplicate_transaction_set_control_number=None, validate_edi_types=None, validate_xsd_types=None, allow_leading_and_trailing_spaces_and_zeroes=None, trim_leading_and_trailing_spaces_and_zeroes=None, trailing_separator_policy=None):
        self.validate_character_set = validate_character_set
        self.check_duplicate_interchange_control_number = check_duplicate_interchange_control_number
        self.interchange_control_number_validity_days = interchange_control_number_validity_days
        self.check_duplicate_group_control_number = check_duplicate_group_control_number
        self.check_duplicate_transaction_set_control_number = check_duplicate_transaction_set_control_number
        self.validate_edi_types = validate_edi_types
        self.validate_xsd_types = validate_xsd_types
        self.allow_leading_and_trailing_spaces_and_zeroes = allow_leading_and_trailing_spaces_and_zeroes
        self.trim_leading_and_trailing_spaces_and_zeroes = trim_leading_and_trailing_spaces_and_zeroes
        self.trailing_separator_policy = trailing_separator_policy
