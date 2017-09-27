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


class SiteMachineKey(Model):
    """MachineKey of an app.

    :param validation: MachineKey validation.
    :type validation: str
    :param validation_key: Validation key.
    :type validation_key: str
    :param decryption: Decryption.
    :type decryption: str
    :param decryption_key: Decryption key.
    :type decryption_key: str
    """

    _attribute_map = {
        'validation': {'key': 'validation', 'type': 'str'},
        'validation_key': {'key': 'validationKey', 'type': 'str'},
        'decryption': {'key': 'decryption', 'type': 'str'},
        'decryption_key': {'key': 'decryptionKey', 'type': 'str'},
    }

    def __init__(self, validation=None, validation_key=None, decryption=None, decryption_key=None):
        self.validation = validation
        self.validation_key = validation_key
        self.decryption = decryption
        self.decryption_key = decryption_key
