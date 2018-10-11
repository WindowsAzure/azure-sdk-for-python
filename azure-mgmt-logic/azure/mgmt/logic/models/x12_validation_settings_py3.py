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
    """The X12 agreement validation settings.

    All required parameters must be populated in order to send to Azure.

    :param validate_character_set: Required. The value indicating whether to
     validate character set in the message.
    :type validate_character_set: bool
    :param check_duplicate_interchange_control_number: Required. The value
     indicating whether to check for duplicate interchange control number.
    :type check_duplicate_interchange_control_number: bool
    :param interchange_control_number_validity_days: Required. The validity
     period of interchange control number.
    :type interchange_control_number_validity_days: int
    :param check_duplicate_group_control_number: Required. The value
     indicating whether to check for duplicate group control number.
    :type check_duplicate_group_control_number: bool
    :param check_duplicate_transaction_set_control_number: Required. The value
     indicating whether to check for duplicate transaction set control number.
    :type check_duplicate_transaction_set_control_number: bool
    :param validate_edi_types: Required. The value indicating whether to
     Whether to validate EDI types.
    :type validate_edi_types: bool
    :param validate_xsd_types: Required. The value indicating whether to
     Whether to validate XSD types.
    :type validate_xsd_types: bool
    :param allow_leading_and_trailing_spaces_and_zeroes: Required. The value
     indicating whether to allow leading and trailing spaces and zeroes.
    :type allow_leading_and_trailing_spaces_and_zeroes: bool
    :param trim_leading_and_trailing_spaces_and_zeroes: Required. The value
     indicating whether to trim leading and trailing spaces and zeroes.
    :type trim_leading_and_trailing_spaces_and_zeroes: bool
    :param trailing_separator_policy: Required. The trailing separator policy.
     Possible values include: 'NotSpecified', 'NotAllowed', 'Optional',
     'Mandatory'
    :type trailing_separator_policy: str or
     ~azure.mgmt.logic.models.TrailingSeparatorPolicy
    """

    _validation = {
        'validate_character_set': {'required': True},
        'check_duplicate_interchange_control_number': {'required': True},
        'interchange_control_number_validity_days': {'required': True},
        'check_duplicate_group_control_number': {'required': True},
        'check_duplicate_transaction_set_control_number': {'required': True},
        'validate_edi_types': {'required': True},
        'validate_xsd_types': {'required': True},
        'allow_leading_and_trailing_spaces_and_zeroes': {'required': True},
        'trim_leading_and_trailing_spaces_and_zeroes': {'required': True},
        'trailing_separator_policy': {'required': True},
    }

    _attribute_map = {
        'validate_character_set': {'key': 'validateCharacterSet', 'type': 'bool'},
        'check_duplicate_interchange_control_number': {'key': 'checkDuplicateInterchangeControlNumber', 'type': 'bool'},
        'interchange_control_number_validity_days': {'key': 'interchangeControlNumberValidityDays', 'type': 'int'},
        'check_duplicate_group_control_number': {'key': 'checkDuplicateGroupControlNumber', 'type': 'bool'},
        'check_duplicate_transaction_set_control_number': {'key': 'checkDuplicateTransactionSetControlNumber', 'type': 'bool'},
        'validate_edi_types': {'key': 'validateEdiTypes', 'type': 'bool'},
        'validate_xsd_types': {'key': 'validateXsdTypes', 'type': 'bool'},
        'allow_leading_and_trailing_spaces_and_zeroes': {'key': 'allowLeadingAndTrailingSpacesAndZeroes', 'type': 'bool'},
        'trim_leading_and_trailing_spaces_and_zeroes': {'key': 'trimLeadingAndTrailingSpacesAndZeroes', 'type': 'bool'},
        'trailing_separator_policy': {'key': 'trailingSeparatorPolicy', 'type': 'str'},
    }

    def __init__(self, *, validate_character_set: bool, check_duplicate_interchange_control_number: bool, interchange_control_number_validity_days: int, check_duplicate_group_control_number: bool, check_duplicate_transaction_set_control_number: bool, validate_edi_types: bool, validate_xsd_types: bool, allow_leading_and_trailing_spaces_and_zeroes: bool, trim_leading_and_trailing_spaces_and_zeroes: bool, trailing_separator_policy, **kwargs) -> None:
        super(X12ValidationSettings, self).__init__(**kwargs)
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
