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


class Volume(Model):
    """Volume resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. Resource location
    :type location: str
    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param tags: Resource tags
    :type tags: object
    :ivar file_system_id: FileSystem ID. Unique FileSystem Identifier.
    :vartype file_system_id: str
    :param creation_token: Required. Creation Token or File Path. A unique
     file path for the volume. Used when creating mount targets
    :type creation_token: str
    :param service_level: Required. serviceLevel. The service level of the
     file system. Possible values include: 'Standard', 'Premium', 'Ultra'.
     Default value: "Premium" .
    :type service_level: str or ~azure.mgmt.netapp.models.ServiceLevel
    :param usage_threshold: usageThreshold. Maximum storage quota allowed for
     a file system in bytes. This is a soft quota used for alerting only.
     Minimum size is 100 GiB. Upper limit is 100TiB. Default value:
     107374182400 .
    :type usage_threshold: long
    :param export_policy: exportPolicy. Set of export policy rules
    :type export_policy:
     ~azure.mgmt.netapp.models.VolumePropertiesExportPolicy
    :ivar provisioning_state: Azure lifecycle management
    :vartype provisioning_state: str
    :param snapshot_id: Snapshot ID. UUID v4 used to identify the Snapshot
    :type snapshot_id: str
    :ivar baremetal_tenant_id: Baremetal Tenant ID. Unique Baremetal Tenant
     Identifier.
    :vartype baremetal_tenant_id: str
    :param subnet_id: The Azure Resource URI for a delegated subnet. Must have
     the delegation Microsoft.NetApp/volumes
    :type subnet_id: str
    """

    _validation = {
        'location': {'required': True},
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'file_system_id': {'readonly': True, 'max_length': 36, 'min_length': 36, 'pattern': r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'},
        'creation_token': {'required': True},
        'service_level': {'required': True},
        'usage_threshold': {'maximum': 109951162777600, 'minimum': 107374182400},
        'provisioning_state': {'readonly': True},
        'snapshot_id': {'max_length': 36, 'min_length': 36, 'pattern': r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'},
        'baremetal_tenant_id': {'readonly': True, 'max_length': 36, 'min_length': 36, 'pattern': r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': 'object'},
        'file_system_id': {'key': 'properties.fileSystemId', 'type': 'str'},
        'creation_token': {'key': 'properties.creationToken', 'type': 'str'},
        'service_level': {'key': 'properties.serviceLevel', 'type': 'str'},
        'usage_threshold': {'key': 'properties.usageThreshold', 'type': 'long'},
        'export_policy': {'key': 'properties.exportPolicy', 'type': 'VolumePropertiesExportPolicy'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'snapshot_id': {'key': 'properties.snapshotId', 'type': 'str'},
        'baremetal_tenant_id': {'key': 'properties.baremetalTenantId', 'type': 'str'},
        'subnet_id': {'key': 'properties.subnetId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Volume, self).__init__(**kwargs)
        self.location = kwargs.get('location', None)
        self.id = None
        self.name = None
        self.type = None
        self.tags = kwargs.get('tags', None)
        self.file_system_id = None
        self.creation_token = kwargs.get('creation_token', None)
        self.service_level = kwargs.get('service_level', "Premium")
        self.usage_threshold = kwargs.get('usage_threshold', 107374182400)
        self.export_policy = kwargs.get('export_policy', None)
        self.provisioning_state = None
        self.snapshot_id = kwargs.get('snapshot_id', None)
        self.baremetal_tenant_id = None
        self.subnet_id = kwargs.get('subnet_id', None)
