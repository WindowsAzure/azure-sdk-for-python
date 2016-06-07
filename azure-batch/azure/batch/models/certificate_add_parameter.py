# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class CertificateAddParameter(Model):
    """
    A certificate that can be installed on compute nodes and can be used to
    authenticate operations on the machine.

    :param thumbprint: The X.509 thumbprint of the certificate. This is a
     sequence of up to 40 hex digits (it may include spaces but these are
     removed).
    :type thumbprint: str
    :param thumbprint_algorithm: The algorithm used to derive the thumbprint.
     This must be sha1.
    :type thumbprint_algorithm: str
    :param data: The base64-encoded contents of the certificate. The maximum
     size is 10KB.
    :type data: str
    :param certificate_format: The format of the certificate data. Possible
     values include: 'pfx', 'cer', 'unmapped'
    :type certificate_format: str or :class:`CertificateFormat
     <azure.batch.models.CertificateFormat>`
    :param password: The password to access the certificate's private key.
    :type password: str
    """ 

    _validation = {
        'thumbprint': {'required': True},
        'thumbprint_algorithm': {'required': True},
        'data': {'required': True},
    }

    _attribute_map = {
        'thumbprint': {'key': 'thumbprint', 'type': 'str'},
        'thumbprint_algorithm': {'key': 'thumbprintAlgorithm', 'type': 'str'},
        'data': {'key': 'data', 'type': 'str'},
        'certificate_format': {'key': 'certificateFormat', 'type': 'CertificateFormat'},
        'password': {'key': 'password', 'type': 'str'},
    }

    def __init__(self, thumbprint, thumbprint_algorithm, data, certificate_format=None, password=None):
        self.thumbprint = thumbprint
        self.thumbprint_algorithm = thumbprint_algorithm
        self.data = data
        self.certificate_format = certificate_format
        self.password = password
