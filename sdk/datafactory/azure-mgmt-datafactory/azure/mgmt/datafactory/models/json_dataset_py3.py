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

from .dataset_py3 import Dataset


class JsonDataset(Dataset):
    """Json dataset.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param description: Dataset description.
    :type description: str
    :param structure: Columns that define the structure of the dataset. Type:
     array (or Expression with resultType array), itemType: DatasetDataElement.
    :type structure: object
    :param schema: Columns that define the physical type schema of the
     dataset. Type: array (or Expression with resultType array), itemType:
     DatasetSchemaDataElement.
    :type schema: object
    :param linked_service_name: Required. Linked service reference.
    :type linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param parameters: Parameters for dataset.
    :type parameters: dict[str,
     ~azure.mgmt.datafactory.models.ParameterSpecification]
    :param annotations: List of tags that can be used for describing the
     Dataset.
    :type annotations: list[object]
    :param folder: The folder that this Dataset is in. If not specified,
     Dataset will appear at the root level.
    :type folder: ~azure.mgmt.datafactory.models.DatasetFolder
    :param type: Required. Constant filled by server.
    :type type: str
    :param location: Required. The location of the json data storage.
    :type location: ~azure.mgmt.datafactory.models.DatasetLocation
    :param encoding_name: The code page name of the preferred encoding. If not
     specified, the default value is UTF-8, unless BOM denotes another Unicode
     encoding. Refer to the name column of the table in the following link to
     set supported values:
     https://msdn.microsoft.com/library/system.text.encoding.aspx. Type: string
     (or Expression with resultType string).
    :type encoding_name: object
    :param compression: The data compression method used for the json dataset.
    :type compression: ~azure.mgmt.datafactory.models.DatasetCompression
    """

    _validation = {
        'linked_service_name': {'required': True},
        'type': {'required': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'description': {'key': 'description', 'type': 'str'},
        'structure': {'key': 'structure', 'type': 'object'},
        'schema': {'key': 'schema', 'type': 'object'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'folder': {'key': 'folder', 'type': 'DatasetFolder'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'typeProperties.location', 'type': 'DatasetLocation'},
        'encoding_name': {'key': 'typeProperties.encodingName', 'type': 'object'},
        'compression': {'key': 'typeProperties.compression', 'type': 'DatasetCompression'},
    }

    def __init__(self, *, linked_service_name, location, additional_properties=None, description: str=None, structure=None, schema=None, parameters=None, annotations=None, folder=None, encoding_name=None, compression=None, **kwargs) -> None:
        super(JsonDataset, self).__init__(additional_properties=additional_properties, description=description, structure=structure, schema=schema, linked_service_name=linked_service_name, parameters=parameters, annotations=annotations, folder=folder, **kwargs)
        self.location = location
        self.encoding_name = encoding_name
        self.compression = compression
        self.type = 'Json'
