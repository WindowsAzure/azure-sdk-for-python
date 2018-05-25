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


class BackupStatusResponse(Model):
    """BackupStatus response.

    :param protection_status: Specifies whether the container is registered or
     not. Possible values include: 'Invalid', 'NotProtected', 'Protecting',
     'Protected', 'ProtectionFailed'
    :type protection_status: str or
     ~azure.mgmt.recoveryservicesbackup.models.ProtectionStatus
    :param vault_id: Specifies the arm resource id of the vault
    :type vault_id: str
    :param fabric_name: Specifies the fabric name - Azure or AAD. Possible
     values include: 'Invalid', 'Azure'
    :type fabric_name: str or
     ~azure.mgmt.recoveryservicesbackup.models.FabricName
    :param container_name: Specifies the product specific container name. E.g.
     iaasvmcontainer;iaasvmcontainer;csname;vmname. This is required for portal
    :type container_name: str
    :param protected_item_name: Specifies the product specific ds name. E.g.
     vm;iaasvmcontainer;csname;vmname. This is required for portal
    :type protected_item_name: str
    :param error_code: ErrorCode in case of intent failed
    :type error_code: str
    :param error_message: ErrorMessage in case of intent failed.
    :type error_message: str
    :param policy_name: Specifies the policy name which is used for protection
    :type policy_name: str
    :param registration_status: Container registration status
    :type registration_status: str
    """

    _attribute_map = {
        'protection_status': {'key': 'protectionStatus', 'type': 'str'},
        'vault_id': {'key': 'vaultId', 'type': 'str'},
        'fabric_name': {'key': 'fabricName', 'type': 'str'},
        'container_name': {'key': 'containerName', 'type': 'str'},
        'protected_item_name': {'key': 'protectedItemName', 'type': 'str'},
        'error_code': {'key': 'errorCode', 'type': 'str'},
        'error_message': {'key': 'errorMessage', 'type': 'str'},
        'policy_name': {'key': 'policyName', 'type': 'str'},
        'registration_status': {'key': 'registrationStatus', 'type': 'str'},
    }

    def __init__(self, *, protection_status=None, vault_id: str=None, fabric_name=None, container_name: str=None, protected_item_name: str=None, error_code: str=None, error_message: str=None, policy_name: str=None, registration_status: str=None, **kwargs) -> None:
        super(BackupStatusResponse, self).__init__(**kwargs)
        self.protection_status = protection_status
        self.vault_id = vault_id
        self.fabric_name = fabric_name
        self.container_name = container_name
        self.protected_item_name = protected_item_name
        self.error_code = error_code
        self.error_message = error_message
        self.policy_name = policy_name
        self.registration_status = registration_status
