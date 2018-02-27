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


class PendingCertificateSigningRequestResult(Model):
    """The pending certificate signing request result.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar value: The pending certificate signing request as Base64 encoded
     string.
    :vartype value: str
    """

    _validation = {
        'value': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self):
        super(PendingCertificateSigningRequestResult, self).__init__()
        self.value = None
