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


class ResponseContract(Model):
    """Operation response details.

    All required parameters must be populated in order to send to Azure.

    :param status_code: Required. Operation response HTTP status code.
    :type status_code: int
    :param description: Operation response description.
    :type description: str
    :param representations: Collection of operation response representations.
    :type representations:
     list[~azure.mgmt.apimanagement.models.RepresentationContract]
    :param headers: Collection of operation response headers.
    :type headers: list[~azure.mgmt.apimanagement.models.ParameterContract]
    """

    _validation = {
        'status_code': {'required': True},
    }

    _attribute_map = {
        'status_code': {'key': 'statusCode', 'type': 'int'},
        'description': {'key': 'description', 'type': 'str'},
        'representations': {'key': 'representations', 'type': '[RepresentationContract]'},
        'headers': {'key': 'headers', 'type': '[ParameterContract]'},
    }

    def __init__(self, **kwargs):
        super(ResponseContract, self).__init__(**kwargs)
        self.status_code = kwargs.get('status_code', None)
        self.description = kwargs.get('description', None)
        self.representations = kwargs.get('representations', None)
        self.headers = kwargs.get('headers', None)
