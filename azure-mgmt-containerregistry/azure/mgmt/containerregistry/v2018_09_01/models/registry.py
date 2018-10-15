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

from .resource import Resource


class Registry(Resource):
    """An object that represents a container registry.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param location: Required. The location of the resource. This cannot be
     changed after the resource is created.
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :param sku: Required. The SKU of the container registry.
    :type sku: ~azure.mgmt.containerregistry.v2018_09_01.models.Sku
    :param identity: The identity of the container registry.
    :type identity:
     ~azure.mgmt.containerregistry.v2018_09_01.models.RegistryIdentity
    :ivar login_server: The URL that can be used to log into the container
     registry.
    :vartype login_server: str
    :ivar creation_date: The creation date of the container registry in
     ISO8601 format.
    :vartype creation_date: datetime
    :ivar provisioning_state: The provisioning state of the container registry
     at the time the operation was called. Possible values include: 'Creating',
     'Updating', 'Deleting', 'Succeeded', 'Failed', 'Canceled'
    :vartype provisioning_state: str or
     ~azure.mgmt.containerregistry.v2018_09_01.models.ProvisioningState
    :ivar status: The status of the container registry at the time the
     operation was called.
    :vartype status: ~azure.mgmt.containerregistry.v2018_09_01.models.Status
    :param admin_user_enabled: The value that indicates whether the admin user
     is enabled. Default value: False .
    :type admin_user_enabled: bool
    :param storage_account: The properties of the storage account for the
     container registry. Only applicable to Classic SKU.
    :type storage_account:
     ~azure.mgmt.containerregistry.v2018_09_01.models.StorageAccountProperties
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'sku': {'required': True},
        'login_server': {'readonly': True},
        'creation_date': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'status': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'identity': {'key': 'identity', 'type': 'RegistryIdentity'},
        'login_server': {'key': 'properties.loginServer', 'type': 'str'},
        'creation_date': {'key': 'properties.creationDate', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'Status'},
        'admin_user_enabled': {'key': 'properties.adminUserEnabled', 'type': 'bool'},
        'storage_account': {'key': 'properties.storageAccount', 'type': 'StorageAccountProperties'},
    }

    def __init__(self, **kwargs):
        super(Registry, self).__init__(**kwargs)
        self.sku = kwargs.get('sku', None)
        self.identity = kwargs.get('identity', None)
        self.login_server = None
        self.creation_date = None
        self.provisioning_state = None
        self.status = None
        self.admin_user_enabled = kwargs.get('admin_user_enabled', False)
        self.storage_account = kwargs.get('storage_account', None)
