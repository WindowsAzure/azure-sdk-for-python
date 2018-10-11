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


class DataBoxHeavySecret(Model):
    """The secrets related to a databox heavy.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar device_serial_number: Serial number of the assigned device.
    :vartype device_serial_number: str
    :ivar device_password: Password for out of the box experience on device.
    :vartype device_password: str
    :ivar network_configurations: Network configuration of the appliance.
    :vartype network_configurations:
     list[~azure.mgmt.databox.models.ApplianceNetworkConfiguration]
    :ivar encoded_validation_cert_pub_key: The base 64 encoded public key to
     authenticate with the device
    :vartype encoded_validation_cert_pub_key: str
    :ivar account_credential_details: Per account level access credentials.
    :vartype account_credential_details:
     list[~azure.mgmt.databox.models.AccountCredentialDetails]
    """

    _validation = {
        'device_serial_number': {'readonly': True},
        'device_password': {'readonly': True},
        'network_configurations': {'readonly': True},
        'encoded_validation_cert_pub_key': {'readonly': True},
        'account_credential_details': {'readonly': True},
    }

    _attribute_map = {
        'device_serial_number': {'key': 'deviceSerialNumber', 'type': 'str'},
        'device_password': {'key': 'devicePassword', 'type': 'str'},
        'network_configurations': {'key': 'networkConfigurations', 'type': '[ApplianceNetworkConfiguration]'},
        'encoded_validation_cert_pub_key': {'key': 'encodedValidationCertPubKey', 'type': 'str'},
        'account_credential_details': {'key': 'accountCredentialDetails', 'type': '[AccountCredentialDetails]'},
    }

    def __init__(self, **kwargs):
        super(DataBoxHeavySecret, self).__init__(**kwargs)
        self.device_serial_number = None
        self.device_password = None
        self.network_configurations = None
        self.encoded_validation_cert_pub_key = None
        self.account_credential_details = None
