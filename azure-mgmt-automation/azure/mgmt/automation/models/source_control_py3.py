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

from .proxy_resource_py3 import ProxyResource


class SourceControl(ProxyResource):
    """Definition of the source control.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param repo_url: Gets or sets the repo url of the source control.
    :type repo_url: str
    :param branch: Gets or sets the repo branch of the source control. Include
     branch as empty string for VsoTfvc.
    :type branch: str
    :param folder_path: Gets or sets the folder path of the source control.
    :type folder_path: str
    :param auto_sync: Gets or sets auto async of the source control. Default
     is false.
    :type auto_sync: bool
    :param publish_runbook: Gets or sets the auto publish of the source
     control. Default is true.
    :type publish_runbook: bool
    :param source_type: The source type. Must be one of VsoGit, VsoTfvc,
     GitHub. Possible values include: 'VsoGit', 'VsoTfvc', 'GitHub'
    :type source_type: str or ~azure.mgmt.automation.models.SourceType
    :param description: Gets or sets the description.
    :type description: str
    :param creation_time: Gets or sets the creation time.
    :type creation_time: datetime
    :param last_modified_time: Gets or sets the last modified time.
    :type last_modified_time: datetime
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'repo_url': {'key': 'properties.repoUrl', 'type': 'str'},
        'branch': {'key': 'properties.branch', 'type': 'str'},
        'folder_path': {'key': 'properties.folderPath', 'type': 'str'},
        'auto_sync': {'key': 'properties.autoSync', 'type': 'bool'},
        'publish_runbook': {'key': 'properties.publishRunbook', 'type': 'bool'},
        'source_type': {'key': 'properties.sourceType', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'last_modified_time': {'key': 'properties.lastModifiedTime', 'type': 'iso-8601'},
    }

    def __init__(self, *, repo_url: str=None, branch: str=None, folder_path: str=None, auto_sync: bool=None, publish_runbook: bool=None, source_type=None, description: str=None, creation_time=None, last_modified_time=None, **kwargs) -> None:
        super(SourceControl, self).__init__(**kwargs)
        self.repo_url = repo_url
        self.branch = branch
        self.folder_path = folder_path
        self.auto_sync = auto_sync
        self.publish_runbook = publish_runbook
        self.source_type = source_type
        self.description = description
        self.creation_time = creation_time
        self.last_modified_time = last_modified_time
