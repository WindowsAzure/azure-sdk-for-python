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


class EdifactAcknowledgementSettings(Model):
    """The Edifact agreement acknowledgement settings.

    :param need_technical_acknowledgement: The value indicating whether
     technical acknowledgement is needed.
    :type need_technical_acknowledgement: bool
    :param batch_technical_acknowledgements: The value indicating whether to
     batch the technical acknowledgements.
    :type batch_technical_acknowledgements: bool
    :param need_functional_acknowledgement: The value indicating whether
     functional acknowledgement is needed.
    :type need_functional_acknowledgement: bool
    :param batch_functional_acknowledgements: The value indicating whether to
     batch functional acknowledgements.
    :type batch_functional_acknowledgements: bool
    :param need_loop_for_valid_messages: The value indicating whether a loop
     is needed for valid messages.
    :type need_loop_for_valid_messages: bool
    :param send_synchronous_acknowledgement: The value indicating whether to
     send synchronous acknowledgement.
    :type send_synchronous_acknowledgement: bool
    :param acknowledgement_control_number_prefix: The acknowledgement control
     number prefix.
    :type acknowledgement_control_number_prefix: str
    :param acknowledgement_control_number_suffix: The acknowledgement control
     number suffix.
    :type acknowledgement_control_number_suffix: str
    :param acknowledgement_control_number_lower_bound: The acknowledgement
     control number lower bound.
    :type acknowledgement_control_number_lower_bound: int
    :param acknowledgement_control_number_upper_bound: The acknowledgement
     control number upper bound.
    :type acknowledgement_control_number_upper_bound: int
    :param rollover_acknowledgement_control_number: The value indicating
     whether to rollover acknowledgement control number.
    :type rollover_acknowledgement_control_number: bool
    """

    _validation = {
        'need_technical_acknowledgement': {'required': True},
        'batch_technical_acknowledgements': {'required': True},
        'need_functional_acknowledgement': {'required': True},
        'batch_functional_acknowledgements': {'required': True},
        'need_loop_for_valid_messages': {'required': True},
        'send_synchronous_acknowledgement': {'required': True},
        'acknowledgement_control_number_lower_bound': {'required': True},
        'acknowledgement_control_number_upper_bound': {'required': True},
        'rollover_acknowledgement_control_number': {'required': True},
    }

    _attribute_map = {
        'need_technical_acknowledgement': {'key': 'needTechnicalAcknowledgement', 'type': 'bool'},
        'batch_technical_acknowledgements': {'key': 'batchTechnicalAcknowledgements', 'type': 'bool'},
        'need_functional_acknowledgement': {'key': 'needFunctionalAcknowledgement', 'type': 'bool'},
        'batch_functional_acknowledgements': {'key': 'batchFunctionalAcknowledgements', 'type': 'bool'},
        'need_loop_for_valid_messages': {'key': 'needLoopForValidMessages', 'type': 'bool'},
        'send_synchronous_acknowledgement': {'key': 'sendSynchronousAcknowledgement', 'type': 'bool'},
        'acknowledgement_control_number_prefix': {'key': 'acknowledgementControlNumberPrefix', 'type': 'str'},
        'acknowledgement_control_number_suffix': {'key': 'acknowledgementControlNumberSuffix', 'type': 'str'},
        'acknowledgement_control_number_lower_bound': {'key': 'acknowledgementControlNumberLowerBound', 'type': 'int'},
        'acknowledgement_control_number_upper_bound': {'key': 'acknowledgementControlNumberUpperBound', 'type': 'int'},
        'rollover_acknowledgement_control_number': {'key': 'rolloverAcknowledgementControlNumber', 'type': 'bool'},
    }

    def __init__(self, need_technical_acknowledgement, batch_technical_acknowledgements, need_functional_acknowledgement, batch_functional_acknowledgements, need_loop_for_valid_messages, send_synchronous_acknowledgement, acknowledgement_control_number_lower_bound, acknowledgement_control_number_upper_bound, rollover_acknowledgement_control_number, acknowledgement_control_number_prefix=None, acknowledgement_control_number_suffix=None):
        super(EdifactAcknowledgementSettings, self).__init__()
        self.need_technical_acknowledgement = need_technical_acknowledgement
        self.batch_technical_acknowledgements = batch_technical_acknowledgements
        self.need_functional_acknowledgement = need_functional_acknowledgement
        self.batch_functional_acknowledgements = batch_functional_acknowledgements
        self.need_loop_for_valid_messages = need_loop_for_valid_messages
        self.send_synchronous_acknowledgement = send_synchronous_acknowledgement
        self.acknowledgement_control_number_prefix = acknowledgement_control_number_prefix
        self.acknowledgement_control_number_suffix = acknowledgement_control_number_suffix
        self.acknowledgement_control_number_lower_bound = acknowledgement_control_number_lower_bound
        self.acknowledgement_control_number_upper_bound = acknowledgement_control_number_upper_bound
        self.rollover_acknowledgement_control_number = rollover_acknowledgement_control_number
