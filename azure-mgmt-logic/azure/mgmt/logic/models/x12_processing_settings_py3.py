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


class X12ProcessingSettings(Model):
    """The X12 processing settings.

    All required parameters must be populated in order to send to Azure.

    :param mask_security_info: Required. The value indicating whether to mask
     security information.
    :type mask_security_info: bool
    :param convert_implied_decimal: Required. The value indicating whether to
     convert numerical type to implied decimal.
    :type convert_implied_decimal: bool
    :param preserve_interchange: Required. The value indicating whether to
     preserve interchange.
    :type preserve_interchange: bool
    :param suspend_interchange_on_error: Required. The value indicating
     whether to suspend interchange on error.
    :type suspend_interchange_on_error: bool
    :param create_empty_xml_tags_for_trailing_separators: Required. The value
     indicating whether to create empty xml tags for trailing separators.
    :type create_empty_xml_tags_for_trailing_separators: bool
    :param use_dot_as_decimal_separator: Required. The value indicating
     whether to use dot as decimal separator.
    :type use_dot_as_decimal_separator: bool
    """

    _validation = {
        'mask_security_info': {'required': True},
        'convert_implied_decimal': {'required': True},
        'preserve_interchange': {'required': True},
        'suspend_interchange_on_error': {'required': True},
        'create_empty_xml_tags_for_trailing_separators': {'required': True},
        'use_dot_as_decimal_separator': {'required': True},
    }

    _attribute_map = {
        'mask_security_info': {'key': 'maskSecurityInfo', 'type': 'bool'},
        'convert_implied_decimal': {'key': 'convertImpliedDecimal', 'type': 'bool'},
        'preserve_interchange': {'key': 'preserveInterchange', 'type': 'bool'},
        'suspend_interchange_on_error': {'key': 'suspendInterchangeOnError', 'type': 'bool'},
        'create_empty_xml_tags_for_trailing_separators': {'key': 'createEmptyXmlTagsForTrailingSeparators', 'type': 'bool'},
        'use_dot_as_decimal_separator': {'key': 'useDotAsDecimalSeparator', 'type': 'bool'},
    }

    def __init__(self, *, mask_security_info: bool, convert_implied_decimal: bool, preserve_interchange: bool, suspend_interchange_on_error: bool, create_empty_xml_tags_for_trailing_separators: bool, use_dot_as_decimal_separator: bool, **kwargs) -> None:
        super(X12ProcessingSettings, self).__init__(**kwargs)
        self.mask_security_info = mask_security_info
        self.convert_implied_decimal = convert_implied_decimal
        self.preserve_interchange = preserve_interchange
        self.suspend_interchange_on_error = suspend_interchange_on_error
        self.create_empty_xml_tags_for_trailing_separators = create_empty_xml_tags_for_trailing_separators
        self.use_dot_as_decimal_separator = use_dot_as_decimal_separator
