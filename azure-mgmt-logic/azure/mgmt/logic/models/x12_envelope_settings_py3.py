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


class X12EnvelopeSettings(Model):
    """The X12 agreement envelope settings.

    All required parameters must be populated in order to send to Azure.

    :param control_standards_id: Required. The controls standards id.
    :type control_standards_id: int
    :param use_control_standards_id_as_repetition_character: Required. The
     value indicating whether to use control standards id as repetition
     character.
    :type use_control_standards_id_as_repetition_character: bool
    :param sender_application_id: Required. The sender application id.
    :type sender_application_id: str
    :param receiver_application_id: Required. The receiver application id.
    :type receiver_application_id: str
    :param control_version_number: Required. The control version number.
    :type control_version_number: str
    :param interchange_control_number_lower_bound: Required. The interchange
     control number lower bound.
    :type interchange_control_number_lower_bound: int
    :param interchange_control_number_upper_bound: Required. The interchange
     control number upper bound.
    :type interchange_control_number_upper_bound: int
    :param rollover_interchange_control_number: Required. The value indicating
     whether to rollover interchange control number.
    :type rollover_interchange_control_number: bool
    :param enable_default_group_headers: Required. The value indicating
     whether to enable default group headers.
    :type enable_default_group_headers: bool
    :param functional_group_id: The functional group id.
    :type functional_group_id: str
    :param group_control_number_lower_bound: Required. The group control
     number lower bound.
    :type group_control_number_lower_bound: int
    :param group_control_number_upper_bound: Required. The group control
     number upper bound.
    :type group_control_number_upper_bound: int
    :param rollover_group_control_number: Required. The value indicating
     whether to rollover group control number.
    :type rollover_group_control_number: bool
    :param group_header_agency_code: Required. The group header agency code.
    :type group_header_agency_code: str
    :param group_header_version: Required. The group header version.
    :type group_header_version: str
    :param transaction_set_control_number_lower_bound: Required. The
     transaction set control number lower bound.
    :type transaction_set_control_number_lower_bound: int
    :param transaction_set_control_number_upper_bound: Required. The
     transaction set control number upper bound.
    :type transaction_set_control_number_upper_bound: int
    :param rollover_transaction_set_control_number: Required. The value
     indicating whether to rollover transaction set control number.
    :type rollover_transaction_set_control_number: bool
    :param transaction_set_control_number_prefix: The transaction set control
     number prefix.
    :type transaction_set_control_number_prefix: str
    :param transaction_set_control_number_suffix: The transaction set control
     number suffix.
    :type transaction_set_control_number_suffix: str
    :param overwrite_existing_transaction_set_control_number: Required. The
     value indicating whether to overwrite existing transaction set control
     number.
    :type overwrite_existing_transaction_set_control_number: bool
    :param group_header_date_format: Required. The group header date format.
     Possible values include: 'NotSpecified', 'CCYYMMDD', 'YYMMDD'
    :type group_header_date_format: str or
     ~azure.mgmt.logic.models.X12DateFormat
    :param group_header_time_format: Required. The group header time format.
     Possible values include: 'NotSpecified', 'HHMM', 'HHMMSS', 'HHMMSSdd',
     'HHMMSSd'
    :type group_header_time_format: str or
     ~azure.mgmt.logic.models.X12TimeFormat
    :param usage_indicator: Required. The usage indicator. Possible values
     include: 'NotSpecified', 'Test', 'Information', 'Production'
    :type usage_indicator: str or ~azure.mgmt.logic.models.UsageIndicator
    """

    _validation = {
        'control_standards_id': {'required': True},
        'use_control_standards_id_as_repetition_character': {'required': True},
        'sender_application_id': {'required': True},
        'receiver_application_id': {'required': True},
        'control_version_number': {'required': True},
        'interchange_control_number_lower_bound': {'required': True},
        'interchange_control_number_upper_bound': {'required': True},
        'rollover_interchange_control_number': {'required': True},
        'enable_default_group_headers': {'required': True},
        'group_control_number_lower_bound': {'required': True},
        'group_control_number_upper_bound': {'required': True},
        'rollover_group_control_number': {'required': True},
        'group_header_agency_code': {'required': True},
        'group_header_version': {'required': True},
        'transaction_set_control_number_lower_bound': {'required': True},
        'transaction_set_control_number_upper_bound': {'required': True},
        'rollover_transaction_set_control_number': {'required': True},
        'overwrite_existing_transaction_set_control_number': {'required': True},
        'group_header_date_format': {'required': True},
        'group_header_time_format': {'required': True},
        'usage_indicator': {'required': True},
    }

    _attribute_map = {
        'control_standards_id': {'key': 'controlStandardsId', 'type': 'int'},
        'use_control_standards_id_as_repetition_character': {'key': 'useControlStandardsIdAsRepetitionCharacter', 'type': 'bool'},
        'sender_application_id': {'key': 'senderApplicationId', 'type': 'str'},
        'receiver_application_id': {'key': 'receiverApplicationId', 'type': 'str'},
        'control_version_number': {'key': 'controlVersionNumber', 'type': 'str'},
        'interchange_control_number_lower_bound': {'key': 'interchangeControlNumberLowerBound', 'type': 'int'},
        'interchange_control_number_upper_bound': {'key': 'interchangeControlNumberUpperBound', 'type': 'int'},
        'rollover_interchange_control_number': {'key': 'rolloverInterchangeControlNumber', 'type': 'bool'},
        'enable_default_group_headers': {'key': 'enableDefaultGroupHeaders', 'type': 'bool'},
        'functional_group_id': {'key': 'functionalGroupId', 'type': 'str'},
        'group_control_number_lower_bound': {'key': 'groupControlNumberLowerBound', 'type': 'int'},
        'group_control_number_upper_bound': {'key': 'groupControlNumberUpperBound', 'type': 'int'},
        'rollover_group_control_number': {'key': 'rolloverGroupControlNumber', 'type': 'bool'},
        'group_header_agency_code': {'key': 'groupHeaderAgencyCode', 'type': 'str'},
        'group_header_version': {'key': 'groupHeaderVersion', 'type': 'str'},
        'transaction_set_control_number_lower_bound': {'key': 'transactionSetControlNumberLowerBound', 'type': 'int'},
        'transaction_set_control_number_upper_bound': {'key': 'transactionSetControlNumberUpperBound', 'type': 'int'},
        'rollover_transaction_set_control_number': {'key': 'rolloverTransactionSetControlNumber', 'type': 'bool'},
        'transaction_set_control_number_prefix': {'key': 'transactionSetControlNumberPrefix', 'type': 'str'},
        'transaction_set_control_number_suffix': {'key': 'transactionSetControlNumberSuffix', 'type': 'str'},
        'overwrite_existing_transaction_set_control_number': {'key': 'overwriteExistingTransactionSetControlNumber', 'type': 'bool'},
        'group_header_date_format': {'key': 'groupHeaderDateFormat', 'type': 'str'},
        'group_header_time_format': {'key': 'groupHeaderTimeFormat', 'type': 'str'},
        'usage_indicator': {'key': 'usageIndicator', 'type': 'str'},
    }

    def __init__(self, *, control_standards_id: int, use_control_standards_id_as_repetition_character: bool, sender_application_id: str, receiver_application_id: str, control_version_number: str, interchange_control_number_lower_bound: int, interchange_control_number_upper_bound: int, rollover_interchange_control_number: bool, enable_default_group_headers: bool, group_control_number_lower_bound: int, group_control_number_upper_bound: int, rollover_group_control_number: bool, group_header_agency_code: str, group_header_version: str, transaction_set_control_number_lower_bound: int, transaction_set_control_number_upper_bound: int, rollover_transaction_set_control_number: bool, overwrite_existing_transaction_set_control_number: bool, group_header_date_format, group_header_time_format, usage_indicator, functional_group_id: str=None, transaction_set_control_number_prefix: str=None, transaction_set_control_number_suffix: str=None, **kwargs) -> None:
        super(X12EnvelopeSettings, self).__init__(**kwargs)
        self.control_standards_id = control_standards_id
        self.use_control_standards_id_as_repetition_character = use_control_standards_id_as_repetition_character
        self.sender_application_id = sender_application_id
        self.receiver_application_id = receiver_application_id
        self.control_version_number = control_version_number
        self.interchange_control_number_lower_bound = interchange_control_number_lower_bound
        self.interchange_control_number_upper_bound = interchange_control_number_upper_bound
        self.rollover_interchange_control_number = rollover_interchange_control_number
        self.enable_default_group_headers = enable_default_group_headers
        self.functional_group_id = functional_group_id
        self.group_control_number_lower_bound = group_control_number_lower_bound
        self.group_control_number_upper_bound = group_control_number_upper_bound
        self.rollover_group_control_number = rollover_group_control_number
        self.group_header_agency_code = group_header_agency_code
        self.group_header_version = group_header_version
        self.transaction_set_control_number_lower_bound = transaction_set_control_number_lower_bound
        self.transaction_set_control_number_upper_bound = transaction_set_control_number_upper_bound
        self.rollover_transaction_set_control_number = rollover_transaction_set_control_number
        self.transaction_set_control_number_prefix = transaction_set_control_number_prefix
        self.transaction_set_control_number_suffix = transaction_set_control_number_suffix
        self.overwrite_existing_transaction_set_control_number = overwrite_existing_transaction_set_control_number
        self.group_header_date_format = group_header_date_format
        self.group_header_time_format = group_header_time_format
        self.usage_indicator = usage_indicator
