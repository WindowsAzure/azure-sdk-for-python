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

from .resource import Resource


class LoggerContract(Resource):
    """Logger details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type for API Management resource.
    :vartype type: str
    :param logger_type: Required. Logger type. Possible values include:
     'azureEventHub', 'applicationInsights'
    :type logger_type: str or ~azure.mgmt.apimanagement.models.LoggerType
    :param description: Logger description.
    :type description: str
    :param credentials: Required. The name and SendRule connection string of
     the event hub for azureEventHub logger.
     Instrumentation key for applicationInsights logger.
    :type credentials: dict[str, str]
    :param is_buffered: Whether records are buffered in the logger before
     publishing. Default is assumed to be true.
    :type is_buffered: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'logger_type': {'required': True},
        'description': {'max_length': 256},
        'credentials': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'logger_type': {'key': 'properties.loggerType', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'credentials': {'key': 'properties.credentials', 'type': '{str}'},
        'is_buffered': {'key': 'properties.isBuffered', 'type': 'bool'},
    }

    def __init__(self, *, logger_type, credentials, description: str=None, is_buffered: bool=None, **kwargs) -> None:
        super(LoggerContract, self).__init__(, **kwargs)
        self.logger_type = logger_type
        self.description = description
        self.credentials = credentials
        self.is_buffered = is_buffered
