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


class AmazonS3Dataset(Dataset):
    """A single Amazon Simple Storage Service (S3) object or a set of S3 objects.

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
     Dataset
    :type annotations: list[object]
    :param folder: The folder that this Dataset is in. If not specified,
     Dataset will appear at the root level.
    :type folder: ~azure.mgmt.datafactory.models.DatasetFolder
    :param type: Required. Constant filled by server.
    :type type: str
    :param bucket_name: Required. The name of the Amazon S3 bucket. Type:
     string (or Expression with resultType string).
    :type bucket_name: object
    :param key: The key of the Amazon S3 object. Type: string (or Expression
     with resultType string).
    :type key: object
    :param prefix: The prefix filter for the S3 object name. Type: string (or
     Expression with resultType string).
    :type prefix: object
    :param version: The version for the S3 object. Type: string (or Expression
     with resultType string).
    :type version: object
    :param modified_datetime_start: The start of S3 object's modified
     datetime. Type: string (or Expression with resultType string).
    :type modified_datetime_start: object
    :param modified_datetime_end: The end of S3 object's modified datetime.
     Type: string (or Expression with resultType string).
    :type modified_datetime_end: object
    :param format: The format of files.
    :type format: ~azure.mgmt.datafactory.models.DatasetStorageFormat
    :param compression: The data compression method used for the Amazon S3
     object.
    :type compression: ~azure.mgmt.datafactory.models.DatasetCompression
    """

    _validation = {
        'linked_service_name': {'required': True},
        'type': {'required': True},
        'bucket_name': {'required': True},
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
        'bucket_name': {'key': 'typeProperties.bucketName', 'type': 'object'},
        'key': {'key': 'typeProperties.key', 'type': 'object'},
        'prefix': {'key': 'typeProperties.prefix', 'type': 'object'},
        'version': {'key': 'typeProperties.version', 'type': 'object'},
        'modified_datetime_start': {'key': 'typeProperties.modifiedDatetimeStart', 'type': 'object'},
        'modified_datetime_end': {'key': 'typeProperties.modifiedDatetimeEnd', 'type': 'object'},
        'format': {'key': 'typeProperties.format', 'type': 'DatasetStorageFormat'},
        'compression': {'key': 'typeProperties.compression', 'type': 'DatasetCompression'},
    }

    def __init__(self, *, linked_service_name, bucket_name, additional_properties=None, description: str=None, structure=None, schema=None, parameters=None, annotations=None, folder=None, key=None, prefix=None, version=None, modified_datetime_start=None, modified_datetime_end=None, format=None, compression=None, **kwargs) -> None:
        super(AmazonS3Dataset, self).__init__(additional_properties=additional_properties, description=description, structure=structure, schema=schema, linked_service_name=linked_service_name, parameters=parameters, annotations=annotations, folder=folder, **kwargs)
        self.bucket_name = bucket_name
        self.key = key
        self.prefix = prefix
        self.version = version
        self.modified_datetime_start = modified_datetime_start
        self.modified_datetime_end = modified_datetime_end
        self.format = format
        self.compression = compression
        self.type = 'AmazonS3Object'
