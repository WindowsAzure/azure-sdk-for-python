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


class RestServiceDataset(Dataset):
    """A Rest service dataset.

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
    :param folder: The folder that this Dataset is in. If not specified,
     Dataset will appear at the root level.
    :type folder: ~azure.mgmt.datafactory.models.DatasetFolder
    :param type: Required. Constant filled by server.
    :type type: str
    :param relative_url: The relative URL to the resource that the RESTful API
     provides. Type: string (or Expression with resultType string).
    :type relative_url: object
    :param request_method: The HTTP method used to call the RESTful API. The
     default is GET. Type: string (or Expression with resultType string).
    :type request_method: object
    :param request_body: The HTTP request body to the RESTful API if
     requestMethod is POST. Type: string (or Expression with resultType
     string).
    :type request_body: object
    :param additional_headers: The additional HTTP headers in the request to
     the RESTful API. Type: string (or Expression with resultType string).
    :type additional_headers: object
    :param pagination_rules: The pagination rules to compose next page
     requests.
    :type pagination_rules: object
    """

    _validation = {
        'linked_service_name': {'required': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'description': {'key': 'description', 'type': 'str'},
        'structure': {'key': 'structure', 'type': 'object'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'folder': {'key': 'folder', 'type': 'DatasetFolder'},
        'type': {'key': 'type', 'type': 'str'},
        'relative_url': {'key': 'typeProperties.relativeUrl', 'type': 'object'},
        'request_method': {'key': 'typeProperties.requestMethod', 'type': 'object'},
        'request_body': {'key': 'typeProperties.requestBody', 'type': 'object'},
        'additional_headers': {'key': 'typeProperties.additionalHeaders', 'type': 'object'},
        'pagination_rules': {'key': 'typeProperties.paginationRules', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(RestServiceDataset, self).__init__(**kwargs)
        self.relative_url = kwargs.get('relative_url', None)
        self.request_method = kwargs.get('request_method', None)
        self.request_body = kwargs.get('request_body', None)
        self.additional_headers = kwargs.get('additional_headers', None)
        self.pagination_rules = kwargs.get('pagination_rules', None)
        self.type = 'RestResource'
