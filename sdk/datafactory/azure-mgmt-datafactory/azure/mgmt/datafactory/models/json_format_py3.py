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

from .dataset_storage_format_py3 import DatasetStorageFormat


class JsonFormat(DatasetStorageFormat):
    """The data stored in JSON format.

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
    :param file_pattern: File pattern of JSON. To be more specific, the way of
     separating a collection of JSON objects. The default value is
     'setOfObjects'. It is case-sensitive.
    :type file_pattern: object
    :param nesting_separator: The character used to separate nesting levels.
     Default value is '.' (dot). Type: string (or Expression with resultType
     string).
    :type nesting_separator: object
    :param encoding_name: The code page name of the preferred encoding. If not
     provided, the default value is 'utf-8', unless the byte order mark (BOM)
     denotes another Unicode encoding. The full list of supported values can be
     found in the 'Name' column of the table of encodings in the following
     reference: https://go.microsoft.com/fwlink/?linkid=861078. Type: string
     (or Expression with resultType string).
    :type encoding_name: object
    :param json_node_reference: The JSONPath of the JSON array element to be
     flattened. Example: "$.ArrayPath". Type: string (or Expression with
     resultType string).
    :type json_node_reference: object
    :param json_path_definition: The JSONPath definition for each column
     mapping with a customized column name to extract data from JSON file. For
     fields under root object, start with "$"; for fields inside the array
     chosen by jsonNodeReference property, start from the array element.
     Example: {"Column1": "$.Column1Path", "Column2": "Column2PathInArray"}.
     Type: object (or Expression with resultType object).
    :type json_path_definition: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'serializer': {'key': 'serializer', 'type': 'object'},
        'deserializer': {'key': 'deserializer', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
        'file_pattern': {'key': 'filePattern', 'type': 'object'},
        'nesting_separator': {'key': 'nestingSeparator', 'type': 'object'},
        'encoding_name': {'key': 'encodingName', 'type': 'object'},
        'json_node_reference': {'key': 'jsonNodeReference', 'type': 'object'},
        'json_path_definition': {'key': 'jsonPathDefinition', 'type': 'object'},
    }

    def __init__(self, *, additional_properties=None, serializer=None, deserializer=None, file_pattern=None, nesting_separator=None, encoding_name=None, json_node_reference=None, json_path_definition=None, **kwargs) -> None:
        super(JsonFormat, self).__init__(additional_properties=additional_properties, serializer=serializer, deserializer=deserializer, **kwargs)
        self.file_pattern = file_pattern
        self.nesting_separator = nesting_separator
        self.encoding_name = encoding_name
        self.json_node_reference = json_node_reference
        self.json_path_definition = json_path_definition
        self.type = 'JsonFormat'
