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
    :param name1: FileSystem name. FileSystem name
    :type name1: str
    :param creation_token: Required. Creation Token or File Path. A unique
     file path for the volume. Used when creating mount targets
    :type creation_token: str
    :param service_level: Required. serviceLevel. The service level of the
     file system. Possible values include: 'Basic', 'Standard', 'Premium'.
     Default value: "Standard" .
    :type service_level: str or ~azure.mgmt.netapp.models.ServiceLevel
    :param usage_threshold: usageThreshold. Maximum storage quota allowed for
     a file system in bytes. This is a soft quota used for alerting only. Upper
     limit is 100TB. Default value: 0 .
    :type usage_threshold: long
    :ivar provisioning_state: Azure lifecycle management
    :vartype provisioning_state: str
    """

    _validation = {
        'location': {'required': True},
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'file_system_id': {'readonly': True, 'max_length': 36, 'min_length': 36, 'pattern': r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'},
        'creation_token': {'required': True},
        'service_level': {'required': True},
        'usage_threshold': {'maximum': 109951162777600, 'minimum': 0},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': 'object'},
        'file_system_id': {'key': 'properties.fileSystemId', 'type': 'str'},
        'name1': {'key': 'properties.name', 'type': 'str'},
        'creation_token': {'key': 'properties.creationToken', 'type': 'str'},
        'service_level': {'key': 'properties.serviceLevel', 'type': 'str'},
        'usage_threshold': {'key': 'properties.usageThreshold', 'type': 'long'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, *, location: str, creation_token: str, tags=None, name1: str=None, service_level="Standard", usage_threshold: int=0, **kwargs) -> None:
        super(Volume, self).__init__(**kwargs)
        self.location = location
        self.id = None
        self.name = None
        self.type = None
        self.tags = tags
        self.file_system_id = None
        self.name1 = name1
        self.creation_token = creation_token
        self.service_level = service_level
        self.usage_threshold = usage_threshold
        self.provisioning_state = None
