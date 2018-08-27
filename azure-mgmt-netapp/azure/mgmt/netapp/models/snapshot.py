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


class Snapshot(Model):
    """Snapshot of a Volume.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. Resource location
    :type location: str
    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :param tags: Resource tags
    :type tags: object
    :ivar snapshot_id: snapshotId. UUID v4 used to identify the Snapshot
    :vartype snapshot_id: str
    :param file_system_id: Required. fileSystemId. UUID v4 used to identify
     the FileSystem
    :type file_system_id: str
    :ivar name1: name. The name of the snapshot
    :vartype name1: str
    :ivar creation_date: name. The creation date of the snapshot
    :vartype creation_date: datetime
    :ivar provisioning_state: Azure lifecycle management
    :vartype provisioning_state: str
    """

    _validation = {
        'location': {'required': True},
        'id': {'readonly': True},
        'name': {'readonly': True},
        'snapshot_id': {'readonly': True, 'max_length': 36, 'min_length': 36, 'pattern': r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'},
        'file_system_id': {'required': True, 'max_length': 36, 'min_length': 36, 'pattern': r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'},
        'name1': {'readonly': True},
        'creation_date': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'tags': {'key': 'tags', 'type': 'object'},
        'snapshot_id': {'key': 'properties.snapshotId', 'type': 'str'},
        'file_system_id': {'key': 'properties.fileSystemId', 'type': 'str'},
        'name1': {'key': 'properties.name', 'type': 'str'},
        'creation_date': {'key': 'properties.creationDate', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Snapshot, self).__init__(**kwargs)
        self.location = kwargs.get('location', None)
        self.id = None
        self.name = None
        self.tags = kwargs.get('tags', None)
        self.snapshot_id = None
        self.file_system_id = kwargs.get('file_system_id', None)
        self.name1 = None
        self.creation_date = None
        self.provisioning_state = None
