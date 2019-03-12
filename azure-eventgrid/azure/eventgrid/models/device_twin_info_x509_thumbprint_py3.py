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


class DeviceTwinInfoX509Thumbprint(Model):
    """The thumbprint is a unique value for the x509 certificate, commonly used to
    find a particular certificate in a certificate store. The thumbprint is
    dynamically generated using the SHA1 algorithm, and does not physically
    exist in the certificate.

    :param primary_thumbprint: Primary thumbprint for the x509 certificate.
    :type primary_thumbprint: str
    :param secondary_thumbprint: Secondary thumbprint for the x509
     certificate.
    :type secondary_thumbprint: str
    """

    _attribute_map = {
        'primary_thumbprint': {'key': 'primaryThumbprint', 'type': 'str'},
        'secondary_thumbprint': {'key': 'secondaryThumbprint', 'type': 'str'},
    }

    def __init__(self, *, primary_thumbprint: str=None, secondary_thumbprint: str=None, **kwargs) -> None:
        super(DeviceTwinInfoX509Thumbprint, self).__init__(**kwargs)
        self.primary_thumbprint = primary_thumbprint
        self.secondary_thumbprint = secondary_thumbprint
