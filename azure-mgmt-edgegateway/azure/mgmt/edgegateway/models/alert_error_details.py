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


class AlertErrorDetails(Model):
    """Error details for the alert.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar error_code: Error code.
    :vartype error_code: str
    :ivar error_message: Error Message.
    :vartype error_message: str
    :ivar occurrences: Number of occurrences.
    :vartype occurrences: int
    """

    _validation = {
        'error_code': {'readonly': True},
        'error_message': {'readonly': True},
        'occurrences': {'readonly': True},
    }

    _attribute_map = {
        'error_code': {'key': 'errorCode', 'type': 'str'},
        'error_message': {'key': 'errorMessage', 'type': 'str'},
        'occurrences': {'key': 'occurrences', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(AlertErrorDetails, self).__init__(**kwargs)
        self.error_code = None
        self.error_message = None
        self.occurrences = None
