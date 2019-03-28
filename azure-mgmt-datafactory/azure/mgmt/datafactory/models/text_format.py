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

from .dataset_storage_format import DatasetStorageFormat


class TextFormat(DatasetStorageFormat):
    """The data stored in text format.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param serializer: Serializer. Type: string (or Expression with resultType
     string).
    :type serializer: object
    :param deserializer: Deserializer. Type: string (or Expression with
     resultType string).
    :type deserializer: object
    :param type: Required. Constant filled by server.
    :type type: str
    :param column_delimiter: The column delimiter. Type: string (or Expression
     with resultType string).
    :type column_delimiter: object
    :param row_delimiter: The row delimiter. Type: string (or Expression with
     resultType string).
    :type row_delimiter: object
    :param escape_char: The escape character. Type: string (or Expression with
     resultType string).
    :type escape_char: object
    :param quote_char: The quote character. Type: string (or Expression with
     resultType string).
    :type quote_char: object
    :param null_value: The null value string. Type: string (or Expression with
     resultType string).
    :type null_value: object
    :param encoding_name: The code page name of the preferred encoding. If
     miss, the default value is ΓÇ£utf-8ΓÇ¥, unless BOM denotes another Unicode
     encoding. Refer to the ΓÇ£NameΓÇ¥ column of the table in the following
     link to set supported values:
     https://msdn.microsoft.com/library/system.text.encoding.aspx. Type: string
     (or Expression with resultType string).
    :type encoding_name: object
    :param treat_empty_as_null: Treat empty column values in the text file as
     null. The default value is true. Type: boolean (or Expression with
     resultType boolean).
    :type treat_empty_as_null: object
    :param skip_line_count: The number of lines/rows to be skipped when
     parsing text files. The default value is 0. Type: integer (or Expression
     with resultType integer).
    :type skip_line_count: object
    :param first_row_as_header: When used as input, treat the first row of
     data as headers. When used as output,write the headers into the output as
     the first row of data. The default value is false. Type: boolean (or
     Expression with resultType boolean).
    :type first_row_as_header: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'serializer': {'key': 'serializer', 'type': 'object'},
        'deserializer': {'key': 'deserializer', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
        'column_delimiter': {'key': 'columnDelimiter', 'type': 'object'},
        'row_delimiter': {'key': 'rowDelimiter', 'type': 'object'},
        'escape_char': {'key': 'escapeChar', 'type': 'object'},
        'quote_char': {'key': 'quoteChar', 'type': 'object'},
        'null_value': {'key': 'nullValue', 'type': 'object'},
        'encoding_name': {'key': 'encodingName', 'type': 'object'},
        'treat_empty_as_null': {'key': 'treatEmptyAsNull', 'type': 'object'},
        'skip_line_count': {'key': 'skipLineCount', 'type': 'object'},
        'first_row_as_header': {'key': 'firstRowAsHeader', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(TextFormat, self).__init__(**kwargs)
        self.column_delimiter = kwargs.get('column_delimiter', None)
        self.row_delimiter = kwargs.get('row_delimiter', None)
        self.escape_char = kwargs.get('escape_char', None)
        self.quote_char = kwargs.get('quote_char', None)
        self.null_value = kwargs.get('null_value', None)
        self.encoding_name = kwargs.get('encoding_name', None)
        self.treat_empty_as_null = kwargs.get('treat_empty_as_null', None)
        self.skip_line_count = kwargs.get('skip_line_count', None)
        self.first_row_as_header = kwargs.get('first_row_as_header', None)
        self.type = 'TextFormat'
