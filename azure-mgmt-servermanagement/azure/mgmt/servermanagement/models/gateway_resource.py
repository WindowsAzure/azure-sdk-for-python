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


class GatewayResource(Resource):
    """Data model for an arm gateway resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Manager Resource ID.
    :vartype id: str
    :ivar type: Resource Manager Resource Type.
    :vartype type: str
    :ivar name: Resource Manager Resource Name.
    :vartype name: str
    :ivar location: Resource Manager Resource Location.
    :vartype location: str
    :param tags: Resource Manager Resource Tags.
    :type tags: dict[str, str]
    :param etag:
    :type etag: str
    :param created: UTC date and time when gateway was first added to
     management service.
    :type created: datetime
    :param updated: UTC date and time when node was last updated.
    :type updated: datetime
    :param upgrade_mode: The upgradeMode property gives the flexibility to
     gateway to auto upgrade itself. If properties value not specified, then we
     assume upgradeMode = Automatic. Possible values include: 'Manual',
     'Automatic'
    :type upgrade_mode: str or ~azure.mgmt.servermanagement.models.UpgradeMode
    :param desired_version: Latest available MSI version.
    :type desired_version: str
    :param instances: Names of the nodes in the gateway.
    :type instances: list[~azure.mgmt.servermanagement.models.GatewayStatus]
    :param active_message_count: Number of active messages.
    :type active_message_count: int
    :param latest_published_msi_version: Last published MSI version.
    :type latest_published_msi_version: str
    :param published_time_utc: The date/time of the last published gateway.
    :type published_time_utc: datetime
    :ivar installer_download: Installer download uri.
    :vartype installer_download: str
    :ivar minimum_version: Minimum gateway version.
    :vartype minimum_version: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'location': {'readonly': True},
        'installer_download': {'readonly': True},
        'minimum_version': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'etag': {'key': 'etag', 'type': 'str'},
        'created': {'key': 'properties.created', 'type': 'iso-8601'},
        'updated': {'key': 'properties.updated', 'type': 'iso-8601'},
        'upgrade_mode': {'key': 'properties.upgradeMode', 'type': 'UpgradeMode'},
        'desired_version': {'key': 'properties.desiredVersion', 'type': 'str'},
        'instances': {'key': 'properties.instances', 'type': '[GatewayStatus]'},
        'active_message_count': {'key': 'properties.activeMessageCount', 'type': 'int'},
        'latest_published_msi_version': {'key': 'properties.latestPublishedMsiVersion', 'type': 'str'},
        'published_time_utc': {'key': 'properties.publishedTimeUtc', 'type': 'iso-8601'},
        'installer_download': {'key': 'properties.installerDownload', 'type': 'str'},
        'minimum_version': {'key': 'properties.minimumVersion', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(GatewayResource, self).__init__(**kwargs)
        self.created = kwargs.get('created', None)
        self.updated = kwargs.get('updated', None)
        self.upgrade_mode = kwargs.get('upgrade_mode', None)
        self.desired_version = kwargs.get('desired_version', None)
        self.instances = kwargs.get('instances', None)
        self.active_message_count = kwargs.get('active_message_count', None)
        self.latest_published_msi_version = kwargs.get('latest_published_msi_version', None)
        self.published_time_utc = kwargs.get('published_time_utc', None)
        self.installer_download = None
        self.minimum_version = None
