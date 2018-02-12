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


class DeleteCertificateError(Model):
    """An error encountered by the Batch service when deleting a certificate.

    :param code: An identifier for the certificate deletion error. Codes are
     invariant and are intended to be consumed programmatically.
    :type code: str
    :param message: A message describing the certificate deletion error,
     intended to be suitable for display in a user interface.
    :type message: str
    :param values: A list of additional error details related to the
     certificate deletion error. This list includes details such as the active
     pools and nodes referencing this certificate. However, if a large number
     of resources reference the certificate, the list contains only about the
     first hundred.
    :type values: list[~azure.batch.models.NameValuePair]
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'values': {'key': 'values', 'type': '[NameValuePair]'},
    }

    def __init__(self, code=None, message=None, values=None):
        super(DeleteCertificateError, self).__init__()
        self.code = code
        self.message = message
        self.values = values
