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

from .tracked_resource import TrackedResource


class DataMigrationService(TrackedResource):
    """A Data Migration Service resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param location: Required. Resource location.
    :type location: str
    :param etag: HTTP strong entity tag value. Ignored if submitted
    :type etag: str
    :param kind: The resource kind. Only 'vm' (the default) is supported.
    :type kind: str
    :ivar provisioning_state: The resource's provisioning state. Possible
     values include: 'Accepted', 'Deleting', 'Deploying', 'Stopped',
     'Stopping', 'Starting', 'FailedToStart', 'FailedToStop', 'Succeeded',
     'Failed'
    :vartype provisioning_state: str or
     ~azure.mgmt.datamigration.models.ServiceProvisioningState
    :param public_key: The public key of the service, used to encrypt secrets
     sent to the service
    :type public_key: str
    :param virtual_subnet_id: Required. The ID of the
     Microsoft.Network/virtualNetworks/subnets resource to which the service
     should be joined
    :type virtual_subnet_id: str
    :param sku: Service SKU
    :type sku: ~azure.mgmt.datamigration.models.ServiceSku
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'virtual_subnet_id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'public_key': {'key': 'properties.publicKey', 'type': 'str'},
        'virtual_subnet_id': {'key': 'properties.virtualSubnetId', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'ServiceSku'},
    }

    def __init__(self, *, location: str, virtual_subnet_id: str, tags=None, etag: str=None, kind: str=None, public_key: str=None, sku=None, **kwargs) -> None:
        super(DataMigrationService, self).__init__(tags=tags, location=location, **kwargs)
        self.etag = etag
        self.kind = kind
        self.provisioning_state = None
        self.public_key = public_key
        self.virtual_subnet_id = virtual_subnet_id
        self.sku = sku
