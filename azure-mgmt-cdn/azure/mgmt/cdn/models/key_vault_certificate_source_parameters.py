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


class KeyVaultCertificateSourceParameters(Model):
    """Describes the parameters for using a user's KeyVault certificate for
    securing custom domain.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar odatatype: Required.  Default value:
     "#Microsoft.Azure.Cdn.Models.KeyVaultCertificateSourceParameters" .
    :vartype odatatype: str
    :param subscription_id: Required. Subscription Id of the user's Key Vault
     containing the SSL certificate
    :type subscription_id: str
    :param resource_group_name: Required. Resource group of the user's Key
     Vault containing the SSL certificate
    :type resource_group_name: str
    :param vault_name: Required. The name of the user's Key Vault containing
     the SSL certificate
    :type vault_name: str
    :param secret_name: Required. The name of Key Vault Secret (representing
     the full certificate PFX) in Key Vault.
    :type secret_name: str
    :param secret_version: Required. The version(GUID) of Key Vault Secret in
     Key Vault.
    :type secret_version: str
    :ivar update_rule: Required. Describes the action that shall be taken when
     the certificate is updated in Key Vault. Default value: "NoAction" .
    :vartype update_rule: str
    :ivar delete_rule: Required. Describes the action that shall be taken when
     the certificate is removed from Key Vault. Default value: "NoAction" .
    :vartype delete_rule: str
    """

    _validation = {
        'odatatype': {'required': True, 'constant': True},
        'subscription_id': {'required': True},
        'resource_group_name': {'required': True},
        'vault_name': {'required': True},
        'secret_name': {'required': True},
        'secret_version': {'required': True},
        'update_rule': {'required': True, 'constant': True},
        'delete_rule': {'required': True, 'constant': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
        'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'},
        'vault_name': {'key': 'vaultName', 'type': 'str'},
        'secret_name': {'key': 'secretName', 'type': 'str'},
        'secret_version': {'key': 'secretVersion', 'type': 'str'},
        'update_rule': {'key': 'updateRule', 'type': 'str'},
        'delete_rule': {'key': 'deleteRule', 'type': 'str'},
    }

    odatatype = "#Microsoft.Azure.Cdn.Models.KeyVaultCertificateSourceParameters"

    update_rule = "NoAction"

    delete_rule = "NoAction"

    def __init__(self, **kwargs):
        super(KeyVaultCertificateSourceParameters, self).__init__(**kwargs)
        self.subscription_id = kwargs.get('subscription_id', None)
        self.resource_group_name = kwargs.get('resource_group_name', None)
        self.vault_name = kwargs.get('vault_name', None)
        self.secret_name = kwargs.get('secret_name', None)
        self.secret_version = kwargs.get('secret_version', None)
