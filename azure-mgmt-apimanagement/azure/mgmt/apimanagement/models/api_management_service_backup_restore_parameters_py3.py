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


class ApiManagementServiceBackupRestoreParameters(Model):
    """Parameters supplied to the Backup/Restore of an API Management service
    operation.

    All required parameters must be populated in order to send to Azure.

    :param storage_account: Required. Azure Cloud Storage account (used to
     place/retrieve the backup) name.
    :type storage_account: str
    :param access_key: Required. Azure Cloud Storage account (used to
     place/retrieve the backup) access key.
    :type access_key: str
    :param container_name: Required. Azure Cloud Storage blob container name
     used to place/retrieve the backup.
    :type container_name: str
    :param backup_name: Required. The name of the backup file to create.
    :type backup_name: str
    """

    _validation = {
        'storage_account': {'required': True},
        'access_key': {'required': True},
        'container_name': {'required': True},
        'backup_name': {'required': True},
    }

    _attribute_map = {
        'storage_account': {'key': 'storageAccount', 'type': 'str'},
        'access_key': {'key': 'accessKey', 'type': 'str'},
        'container_name': {'key': 'containerName', 'type': 'str'},
        'backup_name': {'key': 'backupName', 'type': 'str'},
    }

    def __init__(self, *, storage_account: str, access_key: str, container_name: str, backup_name: str, **kwargs) -> None:
        super(ApiManagementServiceBackupRestoreParameters, self).__init__(**kwargs)
        self.storage_account = storage_account
        self.access_key = access_key
        self.container_name = container_name
        self.backup_name = backup_name
