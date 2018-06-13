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

from .resource_py3 import Resource


class CloudEndpoint(Resource):
    """Cloud Endpoint object.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The id of the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource
    :vartype type: str
    :param storage_account_key: Storage Account access key.
    :type storage_account_key: str
    :param storage_account: Storage Account name.
    :type storage_account: str
    :param storage_account_resource_id: Storage Account Resource Id
    :type storage_account_resource_id: str
    :param storage_account_share_name: Storage Account Share name
    :type storage_account_share_name: str
    :param storage_account_tenant_id: Storage Account Tenant Id
    :type storage_account_tenant_id: str
    :param partnership_id: Partnership Id
    :type partnership_id: str
    :param friendly_name: Friendly Name
    :type friendly_name: str
    :ivar backup_enabled: Backup Enabled
    :vartype backup_enabled: bool
    :param provisioning_state: CloudEndpoint Provisioning State
    :type provisioning_state: str
    :param last_workflow_id: CloudEndpoint lastWorkflowId
    :type last_workflow_id: str
    :param last_operation_name: Resource Last Operation Name
    :type last_operation_name: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'backup_enabled': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'storage_account_key': {'key': 'properties.storageAccountKey', 'type': 'str'},
        'storage_account': {'key': 'properties.storageAccount', 'type': 'str'},
        'storage_account_resource_id': {'key': 'properties.storageAccountResourceId', 'type': 'str'},
        'storage_account_share_name': {'key': 'properties.storageAccountShareName', 'type': 'str'},
        'storage_account_tenant_id': {'key': 'properties.storageAccountTenantId', 'type': 'str'},
        'partnership_id': {'key': 'properties.partnershipId', 'type': 'str'},
        'friendly_name': {'key': 'properties.friendlyName', 'type': 'str'},
        'backup_enabled': {'key': 'properties.backupEnabled', 'type': 'bool'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'last_workflow_id': {'key': 'properties.lastWorkflowId', 'type': 'str'},
        'last_operation_name': {'key': 'properties.lastOperationName', 'type': 'str'},
    }

    def __init__(self, *, storage_account_key: str=None, storage_account: str=None, storage_account_resource_id: str=None, storage_account_share_name: str=None, storage_account_tenant_id: str=None, partnership_id: str=None, friendly_name: str=None, provisioning_state: str=None, last_workflow_id: str=None, last_operation_name: str=None, **kwargs) -> None:
        super(CloudEndpoint, self).__init__(**kwargs)
        self.storage_account_key = storage_account_key
        self.storage_account = storage_account
        self.storage_account_resource_id = storage_account_resource_id
        self.storage_account_share_name = storage_account_share_name
        self.storage_account_tenant_id = storage_account_tenant_id
        self.partnership_id = partnership_id
        self.friendly_name = friendly_name
        self.backup_enabled = None
        self.provisioning_state = provisioning_state
        self.last_workflow_id = last_workflow_id
        self.last_operation_name = last_operation_name
