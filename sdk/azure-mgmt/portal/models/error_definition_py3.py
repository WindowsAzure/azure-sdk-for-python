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


class ErrorDefinition(Model):
    """Error definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: Service specific error code which serves as the substatus for
     the HTTP error code.
    :vartype code: str
    :ivar message: Description of the error.
    :vartype message: str
    :ivar details: Internal error details.
    :vartype details: list[~microsoft.portal.models.ErrorDefinition]
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'details': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorDefinition]'},
    }

    def __init__(self, **kwargs) -> None:
        super(ErrorDefinition, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.details = None
