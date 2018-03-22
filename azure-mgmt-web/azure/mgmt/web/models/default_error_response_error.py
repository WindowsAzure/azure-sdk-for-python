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


class DefaultErrorResponseError(Model):
    """Error model.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: Standardized string to programmatically identify the error.
    :vartype code: str
    :ivar message: Detailed error description and debugging information.
    :vartype message: str
    :ivar target: Detailed error description and debugging information.
    :vartype target: str
    :param details:
    :type details:
     list[~azure.mgmt.web.models.DefaultErrorResponseErrorDetailsItem]
    :ivar innererror: More information to debug error.
    :vartype innererror: str
    """

    _validation = {
        'code': {'required': True, 'readonly': True},
        'message': {'required': True, 'readonly': True},
        'target': {'readonly': True},
        'innererror': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[DefaultErrorResponseErrorDetailsItem]'},
        'innererror': {'key': 'innererror', 'type': 'str'},
    }

    def __init__(self, details=None):
        super(DefaultErrorResponseError, self).__init__()
        self.code = None
        self.message = None
        self.target = None
        self.details = details
        self.innererror = None
