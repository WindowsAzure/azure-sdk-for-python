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


class SiteConfigurationSnapshotInfo(Resource):
    """A snapshot of a web app configuration.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :param name: Resource Name.
    :type name: str
    :param kind: Kind of resource.
    :type kind: str
    :param location: Resource Location.
    :type location: str
    :param type: Resource type.
    :type type: str
    :param tags: Resource tags.
    :type tags: dict
    :ivar time: The time the snapshot was taken.
    :vartype time: datetime
    :ivar site_configuration_snapshot_info_id: The id of the snapshot
    :vartype site_configuration_snapshot_info_id: int
    """

    _validation = {
        'id': {'readonly': True},
        'location': {'required': True},
        'time': {'readonly': True},
        'site_configuration_snapshot_info_id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'time': {'key': 'properties.time', 'type': 'iso-8601'},
        'site_configuration_snapshot_info_id': {'key': 'properties.id', 'type': 'int'},
    }

    def __init__(self, location, name=None, kind=None, type=None, tags=None):
        super(SiteConfigurationSnapshotInfo, self).__init__(name=name, kind=kind, location=location, type=type, tags=tags)
        self.time = None
        self.site_configuration_snapshot_info_id = None
