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


class EmailTemplateContract(Resource):
    """Email Template details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type for API Management resource.
    :vartype type: str
    :param subject: Required. Subject of the Template.
    :type subject: str
    :param body: Required. Email Template Body. This should be a valid
     XDocument
    :type body: str
    :param title: Title of the Template.
    :type title: str
    :param description: Description of the Email Template.
    :type description: str
    :ivar is_default: Whether the template is the default template provided by
     Api Management or has been edited.
    :vartype is_default: bool
    :param parameters: Email Template Parameter values.
    :type parameters:
     list[~azure.mgmt.apimanagement.models.EmailTemplateParametersContractProperties]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'subject': {'required': True, 'max_length': 1000, 'min_length': 1},
        'body': {'required': True, 'min_length': 1},
        'is_default': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'subject': {'key': 'properties.subject', 'type': 'str'},
        'body': {'key': 'properties.body', 'type': 'str'},
        'title': {'key': 'properties.title', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'is_default': {'key': 'properties.isDefault', 'type': 'bool'},
        'parameters': {'key': 'properties.parameters', 'type': '[EmailTemplateParametersContractProperties]'},
    }

    def __init__(self, *, subject: str, body: str, title: str=None, description: str=None, parameters=None, **kwargs) -> None:
        super(EmailTemplateContract, self).__init__(, **kwargs)
        self.subject = subject
        self.body = body
        self.title = title
        self.description = description
        self.is_default = None
        self.parameters = parameters
