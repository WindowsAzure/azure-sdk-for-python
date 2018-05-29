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

from .proxy_only_resource import ProxyOnlyResource


class SiteExtensionInfo(ProxyOnlyResource):
    """Site Extension Information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param extension_id: Site extension ID.
    :type extension_id: str
    :param title:
    :type title: str
    :param extension_type: Site extension type. Possible values include:
     'Gallery', 'WebRoot'
    :type extension_type: str or ~azure.mgmt.web.models.SiteExtensionType
    :param summary: Summary description.
    :type summary: str
    :param description: Detailed description.
    :type description: str
    :param version: Version information.
    :type version: str
    :param extension_url: Extension URL.
    :type extension_url: str
    :param project_url: Project URL.
    :type project_url: str
    :param icon_url: Icon URL.
    :type icon_url: str
    :param license_url: License URL.
    :type license_url: str
    :param feed_url: Feed URL.
    :type feed_url: str
    :param authors: List of authors.
    :type authors: list[str]
    :param installer_command_line_params: Installer command line parameters.
    :type installer_command_line_params: str
    :param published_date_time: Published timestamp.
    :type published_date_time: datetime
    :param download_count: Count of downloads.
    :type download_count: int
    :param local_is_latest_version: <code>true</code> if the local version is
     the latest version; <code>false</code> otherwise.
    :type local_is_latest_version: bool
    :param local_path: Local path.
    :type local_path: str
    :param installed_date_time: Installed timestamp.
    :type installed_date_time: datetime
    :param provisioning_state: Provisioning state.
    :type provisioning_state: str
    :param comment: Site Extension comment.
    :type comment: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'extension_id': {'key': 'properties.extension_id', 'type': 'str'},
        'title': {'key': 'properties.title', 'type': 'str'},
        'extension_type': {'key': 'properties.extension_type', 'type': 'SiteExtensionType'},
        'summary': {'key': 'properties.summary', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'version': {'key': 'properties.version', 'type': 'str'},
        'extension_url': {'key': 'properties.extension_url', 'type': 'str'},
        'project_url': {'key': 'properties.project_url', 'type': 'str'},
        'icon_url': {'key': 'properties.icon_url', 'type': 'str'},
        'license_url': {'key': 'properties.license_url', 'type': 'str'},
        'feed_url': {'key': 'properties.feed_url', 'type': 'str'},
        'authors': {'key': 'properties.authors', 'type': '[str]'},
        'installer_command_line_params': {'key': 'properties.installer_command_line_params', 'type': 'str'},
        'published_date_time': {'key': 'properties.published_date_time', 'type': 'iso-8601'},
        'download_count': {'key': 'properties.download_count', 'type': 'int'},
        'local_is_latest_version': {'key': 'properties.local_is_latest_version', 'type': 'bool'},
        'local_path': {'key': 'properties.local_path', 'type': 'str'},
        'installed_date_time': {'key': 'properties.installed_date_time', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'comment': {'key': 'properties.comment', 'type': 'str'},
    }

    def __init__(self, kind=None, extension_id=None, title=None, extension_type=None, summary=None, description=None, version=None, extension_url=None, project_url=None, icon_url=None, license_url=None, feed_url=None, authors=None, installer_command_line_params=None, published_date_time=None, download_count=None, local_is_latest_version=None, local_path=None, installed_date_time=None, provisioning_state=None, comment=None):
        super(SiteExtensionInfo, self).__init__(kind=kind)
        self.extension_id = extension_id
        self.title = title
        self.extension_type = extension_type
        self.summary = summary
        self.description = description
        self.version = version
        self.extension_url = extension_url
        self.project_url = project_url
        self.icon_url = icon_url
        self.license_url = license_url
        self.feed_url = feed_url
        self.authors = authors
        self.installer_command_line_params = installer_command_line_params
        self.published_date_time = published_date_time
        self.download_count = download_count
        self.local_is_latest_version = local_is_latest_version
        self.local_path = local_path
        self.installed_date_time = installed_date_time
        self.provisioning_state = provisioning_state
        self.comment = comment
