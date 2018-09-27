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


class GalleryImageVersion(Resource):
    """Specifies information about the gallery Image Version that you want to
    create or update.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Required. Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param publishing_profile: Required.
    :type publishing_profile:
     ~azure.mgmt.compute.v2018_06_01.models.GalleryImageVersionPublishingProfile
    :ivar provisioning_state: The current state of the gallery Image Version.
     The provisioning state, which only appears in the response. Possible
     values include: 'Creating', 'Updating', 'Failed', 'Succeeded', 'Deleting',
     'Migrating'
    :vartype provisioning_state: str or
     ~azure.mgmt.compute.v2018_06_01.models.enum
    :ivar storage_profile:
    :vartype storage_profile:
     ~azure.mgmt.compute.v2018_06_01.models.GalleryImageVersionStorageProfile
    :ivar replication_status:
    :vartype replication_status:
     ~azure.mgmt.compute.v2018_06_01.models.ReplicationStatus
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'publishing_profile': {'required': True},
        'provisioning_state': {'readonly': True},
        'storage_profile': {'readonly': True},
        'replication_status': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'publishing_profile': {'key': 'properties.publishingProfile', 'type': 'GalleryImageVersionPublishingProfile'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'storage_profile': {'key': 'properties.storageProfile', 'type': 'GalleryImageVersionStorageProfile'},
        'replication_status': {'key': 'properties.replicationStatus', 'type': 'ReplicationStatus'},
    }

    def __init__(self, *, location: str, publishing_profile, tags=None, **kwargs) -> None:
        super(GalleryImageVersion, self).__init__(location=location, tags=tags, **kwargs)
        self.publishing_profile = publishing_profile
        self.provisioning_state = None
        self.storage_profile = None
        self.replication_status = None
