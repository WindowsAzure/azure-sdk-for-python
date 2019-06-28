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

from .tracked_resource_py3 import TrackedResource


class SqlVirtualMachine(TrackedResource):
    """A SQL virtual machine.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Required. Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param identity: Azure Active Directory identity of the server.
    :type identity: ~azure.mgmt.sqlvirtualmachine.models.ResourceIdentity
    :param virtual_machine_resource_id: ARM Resource id of underlying virtual
     machine created from SQL marketplace image.
    :type virtual_machine_resource_id: str
    :ivar provisioning_state: Provisioning state to track the async operation
     status.
    :vartype provisioning_state: str
    :ivar sql_image_offer: SQL image offer. Examples include SQL2016-WS2016,
     SQL2017-WS2016.
    :vartype sql_image_offer: str
    :param sql_server_license_type: SQL Server license type. Possible values
     include: 'PAYG', 'AHUB'
    :type sql_server_license_type: str or
     ~azure.mgmt.sqlvirtualmachine.models.SqlServerLicenseType
    :param sql_image_sku: SQL Server edition type. Possible values include:
     'Developer', 'Express', 'Standard', 'Enterprise', 'Web'
    :type sql_image_sku: str or
     ~azure.mgmt.sqlvirtualmachine.models.SqlImageSku
    :param sql_virtual_machine_group_resource_id: ARM resource id of the SQL
     virtual machine group this SQL virtual machine is or will be part of.
    :type sql_virtual_machine_group_resource_id: str
    :param wsfc_domain_credentials: Domain credentials for setting up Windows
     Server Failover Cluster for SQL availability group.
    :type wsfc_domain_credentials:
     ~azure.mgmt.sqlvirtualmachine.models.WsfcDomainCredentials
    :param auto_patching_settings: Auto patching settings for applying
     critical security updates to SQL virtual machine.
    :type auto_patching_settings:
     ~azure.mgmt.sqlvirtualmachine.models.AutoPatchingSettings
    :param auto_backup_settings: Auto backup settings for SQL Server.
    :type auto_backup_settings:
     ~azure.mgmt.sqlvirtualmachine.models.AutoBackupSettings
    :param key_vault_credential_settings: Key vault credential settings.
    :type key_vault_credential_settings:
     ~azure.mgmt.sqlvirtualmachine.models.KeyVaultCredentialSettings
    :param server_configurations_management_settings: SQL Server configuration
     management settings.
    :type server_configurations_management_settings:
     ~azure.mgmt.sqlvirtualmachine.models.ServerConfigurationsManagementSettings
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'sql_image_offer': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'identity': {'key': 'identity', 'type': 'ResourceIdentity'},
        'virtual_machine_resource_id': {'key': 'properties.virtualMachineResourceId', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'sql_image_offer': {'key': 'properties.sqlImageOffer', 'type': 'str'},
        'sql_server_license_type': {'key': 'properties.sqlServerLicenseType', 'type': 'str'},
        'sql_image_sku': {'key': 'properties.sqlImageSku', 'type': 'str'},
        'sql_virtual_machine_group_resource_id': {'key': 'properties.sqlVirtualMachineGroupResourceId', 'type': 'str'},
        'wsfc_domain_credentials': {'key': 'properties.wsfcDomainCredentials', 'type': 'WsfcDomainCredentials'},
        'auto_patching_settings': {'key': 'properties.autoPatchingSettings', 'type': 'AutoPatchingSettings'},
        'auto_backup_settings': {'key': 'properties.autoBackupSettings', 'type': 'AutoBackupSettings'},
        'key_vault_credential_settings': {'key': 'properties.keyVaultCredentialSettings', 'type': 'KeyVaultCredentialSettings'},
        'server_configurations_management_settings': {'key': 'properties.serverConfigurationsManagementSettings', 'type': 'ServerConfigurationsManagementSettings'},
    }

    def __init__(self, *, location: str, tags=None, identity=None, virtual_machine_resource_id: str=None, sql_server_license_type=None, sql_image_sku=None, sql_virtual_machine_group_resource_id: str=None, wsfc_domain_credentials=None, auto_patching_settings=None, auto_backup_settings=None, key_vault_credential_settings=None, server_configurations_management_settings=None, **kwargs) -> None:
        super(SqlVirtualMachine, self).__init__(location=location, tags=tags, **kwargs)
        self.identity = identity
        self.virtual_machine_resource_id = virtual_machine_resource_id
        self.provisioning_state = None
        self.sql_image_offer = None
        self.sql_server_license_type = sql_server_license_type
        self.sql_image_sku = sql_image_sku
        self.sql_virtual_machine_group_resource_id = sql_virtual_machine_group_resource_id
        self.wsfc_domain_credentials = wsfc_domain_credentials
        self.auto_patching_settings = auto_patching_settings
        self.auto_backup_settings = auto_backup_settings
        self.key_vault_credential_settings = key_vault_credential_settings
        self.server_configurations_management_settings = server_configurations_management_settings
