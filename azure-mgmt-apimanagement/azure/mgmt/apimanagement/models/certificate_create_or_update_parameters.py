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


class CertificateCreateOrUpdateParameters(Model):
    """Certificate create or update details.

    All required parameters must be populated in order to send to Azure.

    :param data: Required. Base 64 encoded certificate using the
     application/x-pkcs12 representation.
    :type data: str
    :param password: Required. Password for the Certificate
    :type password: str
    """

    _validation = {
        'data': {'required': True},
        'password': {'required': True},
    }

    _attribute_map = {
        'data': {'key': 'properties.data', 'type': 'str'},
        'password': {'key': 'properties.password', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(CertificateCreateOrUpdateParameters, self).__init__(**kwargs)
        self.data = kwargs.get('data', None)
        self.password = kwargs.get('password', None)
