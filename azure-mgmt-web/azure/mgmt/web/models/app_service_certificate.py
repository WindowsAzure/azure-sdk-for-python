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


class AppServiceCertificate(Model):
    """Key Vault container for a certificate that is purchased through Azure.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param key_vault_id: Key Vault resource Id.
    :type key_vault_id: str
    :param key_vault_secret_name: Key Vault secret name.
    :type key_vault_secret_name: str
    :ivar provisioning_state: Status of the Key Vault secret. Possible values
     include: 'Initialized', 'WaitingOnCertificateOrder', 'Succeeded',
     'CertificateOrderFailed', 'OperationNotPermittedOnKeyVault',
     'AzureServiceUnauthorizedToAccessKeyVault', 'KeyVaultDoesNotExist',
     'KeyVaultSecretDoesNotExist', 'UnknownError', 'ExternalPrivateKey',
     'Unknown'
    :vartype provisioning_state: str or :class:`KeyVaultSecretStatus
     <azure.mgmt.web.models.KeyVaultSecretStatus>`
    """

    _validation = {
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'key_vault_id': {'key': 'keyVaultId', 'type': 'str'},
        'key_vault_secret_name': {'key': 'keyVaultSecretName', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'KeyVaultSecretStatus'},
    }

    def __init__(self, key_vault_id=None, key_vault_secret_name=None):
        self.key_vault_id = key_vault_id
        self.key_vault_secret_name = key_vault_secret_name
        self.provisioning_state = None
