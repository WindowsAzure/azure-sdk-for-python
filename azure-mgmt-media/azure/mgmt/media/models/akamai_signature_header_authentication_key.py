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


class AkamaiSignatureHeaderAuthenticationKey(Model):
    """Akamai Signature Header authentication key.

    :param identifier: identifier of the key
    :type identifier: str
    :param base64_key: authentication key
    :type base64_key: str
    :param expiration: The exact time the authentication key.
    :type expiration: datetime
    """

    _attribute_map = {
        'identifier': {'key': 'identifier', 'type': 'str'},
        'base64_key': {'key': 'base64Key', 'type': 'str'},
        'expiration': {'key': 'expiration', 'type': 'iso-8601'},
    }

    def __init__(self, **kwargs):
        super(AkamaiSignatureHeaderAuthenticationKey, self).__init__(**kwargs)
        self.identifier = kwargs.get('identifier', None)
        self.base64_key = kwargs.get('base64_key', None)
        self.expiration = kwargs.get('expiration', None)
