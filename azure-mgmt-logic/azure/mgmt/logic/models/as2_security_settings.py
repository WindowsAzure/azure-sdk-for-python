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


class AS2SecuritySettings(Model):
    """The AS2 agreement security settings.

    :param override_group_signing_certificate: The value indicating whether to
     send or request a MDN.
    :type override_group_signing_certificate: bool
    :param signing_certificate_name: The name of the signing certificate.
    :type signing_certificate_name: str
    :param encryption_certificate_name: The name of the encryption
     certificate.
    :type encryption_certificate_name: str
    :param enable_nrr_for_inbound_encoded_messages: The value indicating
     whether to enable NRR for inbound encoded messages.
    :type enable_nrr_for_inbound_encoded_messages: bool
    :param enable_nrr_for_inbound_decoded_messages: The value indicating
     whether to enable NRR for inbound decoded messages.
    :type enable_nrr_for_inbound_decoded_messages: bool
    :param enable_nrr_for_outbound_mdn: The value indicating whether to enable
     NRR for outbound MDN.
    :type enable_nrr_for_outbound_mdn: bool
    :param enable_nrr_for_outbound_encoded_messages: The value indicating
     whether to enable NRR for outbound encoded messages.
    :type enable_nrr_for_outbound_encoded_messages: bool
    :param enable_nrr_for_outbound_decoded_messages: The value indicating
     whether to enable NRR for outbound decoded messages.
    :type enable_nrr_for_outbound_decoded_messages: bool
    :param enable_nrr_for_inbound_mdn: The value indicating whether to enable
     NRR for inbound MDN.
    :type enable_nrr_for_inbound_mdn: bool
    :param sha2_algorithm_format: The Sha2 algorithm format. Valid values are
     Sha2, ShaHashSize, ShaHyphenHashSize, Sha2UnderscoreHashSize.
    :type sha2_algorithm_format: str
    """

    _validation = {
        'override_group_signing_certificate': {'required': True},
        'enable_nrr_for_inbound_encoded_messages': {'required': True},
        'enable_nrr_for_inbound_decoded_messages': {'required': True},
        'enable_nrr_for_outbound_mdn': {'required': True},
        'enable_nrr_for_outbound_encoded_messages': {'required': True},
        'enable_nrr_for_outbound_decoded_messages': {'required': True},
        'enable_nrr_for_inbound_mdn': {'required': True},
    }

    _attribute_map = {
        'override_group_signing_certificate': {'key': 'overrideGroupSigningCertificate', 'type': 'bool'},
        'signing_certificate_name': {'key': 'signingCertificateName', 'type': 'str'},
        'encryption_certificate_name': {'key': 'encryptionCertificateName', 'type': 'str'},
        'enable_nrr_for_inbound_encoded_messages': {'key': 'enableNrrForInboundEncodedMessages', 'type': 'bool'},
        'enable_nrr_for_inbound_decoded_messages': {'key': 'enableNrrForInboundDecodedMessages', 'type': 'bool'},
        'enable_nrr_for_outbound_mdn': {'key': 'enableNrrForOutboundMdn', 'type': 'bool'},
        'enable_nrr_for_outbound_encoded_messages': {'key': 'enableNrrForOutboundEncodedMessages', 'type': 'bool'},
        'enable_nrr_for_outbound_decoded_messages': {'key': 'enableNrrForOutboundDecodedMessages', 'type': 'bool'},
        'enable_nrr_for_inbound_mdn': {'key': 'enableNrrForInboundMdn', 'type': 'bool'},
        'sha2_algorithm_format': {'key': 'sha2AlgorithmFormat', 'type': 'str'},
    }

    def __init__(self, override_group_signing_certificate, enable_nrr_for_inbound_encoded_messages, enable_nrr_for_inbound_decoded_messages, enable_nrr_for_outbound_mdn, enable_nrr_for_outbound_encoded_messages, enable_nrr_for_outbound_decoded_messages, enable_nrr_for_inbound_mdn, signing_certificate_name=None, encryption_certificate_name=None, sha2_algorithm_format=None):
        self.override_group_signing_certificate = override_group_signing_certificate
        self.signing_certificate_name = signing_certificate_name
        self.encryption_certificate_name = encryption_certificate_name
        self.enable_nrr_for_inbound_encoded_messages = enable_nrr_for_inbound_encoded_messages
        self.enable_nrr_for_inbound_decoded_messages = enable_nrr_for_inbound_decoded_messages
        self.enable_nrr_for_outbound_mdn = enable_nrr_for_outbound_mdn
        self.enable_nrr_for_outbound_encoded_messages = enable_nrr_for_outbound_encoded_messages
        self.enable_nrr_for_outbound_decoded_messages = enable_nrr_for_outbound_decoded_messages
        self.enable_nrr_for_inbound_mdn = enable_nrr_for_inbound_mdn
        self.sha2_algorithm_format = sha2_algorithm_format
