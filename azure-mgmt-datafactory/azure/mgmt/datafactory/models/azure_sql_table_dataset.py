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


class AzureSqlTableDataset(Dataset):
    """The Azure SQL Server database dataset.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param description: Dataset description.
    :type description: str
    :param structure: Columns that define the structure of the dataset. Type:
     array (or Expression with resultType array), itemType: DatasetDataElement.
    :type structure: object
    :param linked_service_name: Linked service reference.
    :type linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param parameters: Parameters for dataset.
    :type parameters: dict[str,
     ~azure.mgmt.datafactory.models.ParameterSpecification]
    :param annotations: List of tags that can be used for describing the
     Dataset.
    :type annotations: list[object]
    :param type: Constant filled by server.
    :type type: str
    :param table_name: The table name of the Azure SQL database. Type: string
     (or Expression with resultType string).
    :type table_name: object
    """

    _validation = {
        'linked_service_name': {'required': True},
        'type': {'required': True},
        'table_name': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'description': {'key': 'description', 'type': 'str'},
        'structure': {'key': 'structure', 'type': 'object'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'table_name': {'key': 'typeProperties.tableName', 'type': 'object'},
    }

    def __init__(self, linked_service_name, table_name, additional_properties=None, description=None, structure=None, parameters=None, annotations=None):
        super(AzureSqlTableDataset, self).__init__(additional_properties=additional_properties, description=description, structure=structure, linked_service_name=linked_service_name, parameters=parameters, annotations=annotations)
        self.table_name = table_name
        self.type = 'AzureSqlTable'
