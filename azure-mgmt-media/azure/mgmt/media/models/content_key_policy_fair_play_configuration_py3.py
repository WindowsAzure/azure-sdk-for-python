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

from .content_key_policy_configuration_py3 import ContentKeyPolicyConfiguration


class ContentKeyPolicyFairPlayConfiguration(ContentKeyPolicyConfiguration):
    """Specifies a configuration for FairPlay licenses.

    All required parameters must be populated in order to send to Azure.

    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param ask: Required. The key that must be used as FairPlay ASk.
    :type ask: bytearray
    :param fair_play_pfx_password: Required. The password encrypting FairPlay
     certificate in PKCS 12 (pfx) format.
    :type fair_play_pfx_password: str
    :param fair_play_pfx: Required. The Base64 representation of FairPlay
     certificate in PKCS 12 (pfx) format (including private key).
    :type fair_play_pfx: str
    :param rental_and_lease_key_type: Required. The rental and lease key type.
     Possible values include: 'Unknown', 'Undefined', 'PersistentUnlimited',
     'PersistentLimited'
    :type rental_and_lease_key_type: str or
     ~azure.mgmt.media.models.ContentKeyPolicyFairPlayRentalAndLeaseKeyType
    :param rental_duration: Required. The rental duration. Must be greater
     than or equal to 0.
    :type rental_duration: long
    """

    _validation = {
        'odatatype': {'required': True},
        'ask': {'required': True},
        'fair_play_pfx_password': {'required': True},
        'fair_play_pfx': {'required': True},
        'rental_and_lease_key_type': {'required': True},
        'rental_duration': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'ask': {'key': 'ask', 'type': 'bytearray'},
        'fair_play_pfx_password': {'key': 'fairPlayPfxPassword', 'type': 'str'},
        'fair_play_pfx': {'key': 'fairPlayPfx', 'type': 'str'},
        'rental_and_lease_key_type': {'key': 'rentalAndLeaseKeyType', 'type': 'ContentKeyPolicyFairPlayRentalAndLeaseKeyType'},
        'rental_duration': {'key': 'rentalDuration', 'type': 'long'},
    }

    def __init__(self, *, ask: bytearray, fair_play_pfx_password: str, fair_play_pfx: str, rental_and_lease_key_type, rental_duration: int, **kwargs) -> None:
        super(ContentKeyPolicyFairPlayConfiguration, self).__init__(**kwargs)
        self.ask = ask
        self.fair_play_pfx_password = fair_play_pfx_password
        self.fair_play_pfx = fair_play_pfx
        self.rental_and_lease_key_type = rental_and_lease_key_type
        self.rental_duration = rental_duration
        self.odatatype = '#Microsoft.Media.ContentKeyPolicyFairPlayConfiguration'
