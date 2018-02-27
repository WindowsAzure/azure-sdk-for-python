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


class ODataError(Model):
    """Error information in OData format.

    :param code: The machine-readable description of the error, such as
     'InvalidRequest' or 'InternalServerError'
    :type code: str
    :param message: The human-readable description of the error
    :type message: str
    :param details: Inner errors that caused this error
    :type details: list[~azure.mgmt.datamigration.models.ODataError]
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ODataError]'},
    }

    def __init__(self, code=None, message=None, details=None):
        super(ODataError, self).__init__()
        self.code = code
        self.message = message
        self.details = details
