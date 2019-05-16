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


class CertificateUpdateParameters(Model):
    """The parameters supplied to the update certificate operation.

    :param name: Gets or sets the name of the certificate.
    :type name: str
    :param description: Gets or sets the description of the certificate.
    :type description: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, description: str=None, **kwargs) -> None:
        super(CertificateUpdateParameters, self).__init__(**kwargs)
        self.name = name
        self.description = description
