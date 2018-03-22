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

from .dataset import Dataset


class AzureDataLakeStoreDataset(Dataset):
    """Azure Data Lake Store dataset.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param description: Dataset description.
    :type description: str
    :param structure: Columns that define the structure of the dataset. Type:
     array (or Expression with resultType array), itemType: DatasetDataElement.
    :type structure: object
    :param linked_service_name: Required. Linked service reference.
    :type linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param parameters: Parameters for dataset.
    :type parameters: dict[str,
     ~azure.mgmt.datafactory.models.ParameterSpecification]
    :param annotations: List of tags that can be used for describing the
     Dataset.
    :type annotations: list[object]
    :param type: Required. Constant filled by server.
    :type type: str
    :param folder_path: Required. Path to the folder in the Azure Data Lake
     Store. Type: string (or Expression with resultType string).
    :type folder_path: object
    :param file_name: The name of the file in the Azure Data Lake Store. Type:
     string (or Expression with resultType string).
    :type file_name: object
    :param format: The format of the Data Lake Store.
    :type format: ~azure.mgmt.datafactory.models.DatasetStorageFormat
    :param compression: The data compression method used for the item(s) in
     the Azure Data Lake Store.
    :type compression: ~azure.mgmt.datafactory.models.DatasetCompression
    """

    _validation = {
        'linked_service_name': {'required': True},
        'type': {'required': True},
        'folder_path': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'description': {'key': 'description', 'type': 'str'},
        'structure': {'key': 'structure', 'type': 'object'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'folder_path': {'key': 'typeProperties.folderPath', 'type': 'object'},
        'file_name': {'key': 'typeProperties.fileName', 'type': 'object'},
        'format': {'key': 'typeProperties.format', 'type': 'DatasetStorageFormat'},
        'compression': {'key': 'typeProperties.compression', 'type': 'DatasetCompression'},
    }

    def __init__(self, **kwargs):
        super(AzureDataLakeStoreDataset, self).__init__(**kwargs)
        self.folder_path = kwargs.get('folder_path', None)
        self.file_name = kwargs.get('file_name', None)
        self.format = kwargs.get('format', None)
        self.compression = kwargs.get('compression', None)
        self.type = 'AzureDataLakeStoreFile'
