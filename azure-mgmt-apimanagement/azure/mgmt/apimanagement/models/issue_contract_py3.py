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

from .resource_py3 import Resource


class IssueContract(Resource):
    """Issue Contract details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type for API Management resource.
    :vartype type: str
    :param title: Required. The issue title.
    :type title: str
    :param description: Required. Text describing the issue.
    :type description: str
    :param created_date: Date and time when the issue was created.
    :type created_date: datetime
    :param state: Status of the issue. Possible values include: 'proposed',
     'open', 'removed', 'resolved', 'closed'
    :type state: str or ~azure.mgmt.apimanagement.models.State
    :param user_id: Required. A resource identifier for the user created the
     issue.
    :type user_id: str
    :param api_id: A resource identifier for the API the issue was created
     for.
    :type api_id: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'title': {'required': True},
        'description': {'required': True},
        'user_id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'title': {'key': 'properties.title', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'created_date': {'key': 'properties.createdDate', 'type': 'iso-8601'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'user_id': {'key': 'properties.userId', 'type': 'str'},
        'api_id': {'key': 'properties.apiId', 'type': 'str'},
    }

    def __init__(self, *, title: str, description: str, user_id: str, created_date=None, state=None, api_id: str=None, **kwargs) -> None:
        super(IssueContract, self).__init__(**kwargs)
        self.title = title
        self.description = description
        self.created_date = created_date
        self.state = state
        self.user_id = user_id
        self.api_id = api_id
