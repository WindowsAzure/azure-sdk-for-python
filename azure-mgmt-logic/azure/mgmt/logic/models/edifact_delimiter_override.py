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


class EdifactDelimiterOverride(Model):
    """The Edifact delimiter override settings.

    All required parameters must be populated in order to send to Azure.

    :param message_id: The message id.
    :type message_id: str
    :param message_version: The message version.
    :type message_version: str
    :param message_release: The message release.
    :type message_release: str
    :param data_element_separator: Required. The data element separator.
    :type data_element_separator: int
    :param component_separator: Required. The component separator.
    :type component_separator: int
    :param segment_terminator: Required. The segment terminator.
    :type segment_terminator: int
    :param repetition_separator: Required. The repetition separator.
    :type repetition_separator: int
    :param segment_terminator_suffix: Required. The segment terminator suffix.
     Possible values include: 'NotSpecified', 'None', 'CR', 'LF', 'CRLF'
    :type segment_terminator_suffix: str or
     ~azure.mgmt.logic.models.SegmentTerminatorSuffix
    :param decimal_point_indicator: Required. The decimal point indicator.
     Possible values include: 'NotSpecified', 'Comma', 'Decimal'
    :type decimal_point_indicator: str or
     ~azure.mgmt.logic.models.EdifactDecimalIndicator
    :param release_indicator: Required. The release indicator.
    :type release_indicator: int
    :param message_association_assigned_code: The message association assigned
     code.
    :type message_association_assigned_code: str
    :param target_namespace: The target namespace on which this delimiter
     settings has to be applied.
    :type target_namespace: str
    """

    _validation = {
        'data_element_separator': {'required': True},
        'component_separator': {'required': True},
        'segment_terminator': {'required': True},
        'repetition_separator': {'required': True},
        'segment_terminator_suffix': {'required': True},
        'decimal_point_indicator': {'required': True},
        'release_indicator': {'required': True},
    }

    _attribute_map = {
        'message_id': {'key': 'messageId', 'type': 'str'},
        'message_version': {'key': 'messageVersion', 'type': 'str'},
        'message_release': {'key': 'messageRelease', 'type': 'str'},
        'data_element_separator': {'key': 'dataElementSeparator', 'type': 'int'},
        'component_separator': {'key': 'componentSeparator', 'type': 'int'},
        'segment_terminator': {'key': 'segmentTerminator', 'type': 'int'},
        'repetition_separator': {'key': 'repetitionSeparator', 'type': 'int'},
        'segment_terminator_suffix': {'key': 'segmentTerminatorSuffix', 'type': 'str'},
        'decimal_point_indicator': {'key': 'decimalPointIndicator', 'type': 'str'},
        'release_indicator': {'key': 'releaseIndicator', 'type': 'int'},
        'message_association_assigned_code': {'key': 'messageAssociationAssignedCode', 'type': 'str'},
        'target_namespace': {'key': 'targetNamespace', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(EdifactDelimiterOverride, self).__init__(**kwargs)
        self.message_id = kwargs.get('message_id', None)
        self.message_version = kwargs.get('message_version', None)
        self.message_release = kwargs.get('message_release', None)
        self.data_element_separator = kwargs.get('data_element_separator', None)
        self.component_separator = kwargs.get('component_separator', None)
        self.segment_terminator = kwargs.get('segment_terminator', None)
        self.repetition_separator = kwargs.get('repetition_separator', None)
        self.segment_terminator_suffix = kwargs.get('segment_terminator_suffix', None)
        self.decimal_point_indicator = kwargs.get('decimal_point_indicator', None)
        self.release_indicator = kwargs.get('release_indicator', None)
        self.message_association_assigned_code = kwargs.get('message_association_assigned_code', None)
        self.target_namespace = kwargs.get('target_namespace', None)
