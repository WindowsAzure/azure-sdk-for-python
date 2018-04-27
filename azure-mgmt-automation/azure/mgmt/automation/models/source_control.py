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


class SourceControl(Model):
    """Definition of the source control.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Resource name.
    :vartype name: str
    :ivar id: Resource Id.
    :vartype id: str
    :ivar type: Resource type.
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
        'name': {'readonly': True},
        'id': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
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

    def __init__(self, **kwargs):
        super(SourceControl, self).__init__(**kwargs)
        self.name = None
        self.id = None
        self.type = None
        self.repo_url = kwargs.get('repo_url', None)
        self.branch = kwargs.get('branch', None)
        self.folder_path = kwargs.get('folder_path', None)
        self.auto_sync = kwargs.get('auto_sync', None)
        self.publish_runbook = kwargs.get('publish_runbook', None)
        self.source_type = kwargs.get('source_type', None)
        self.description = kwargs.get('description', None)
        self.creation_time = kwargs.get('creation_time', None)
        self.last_modified_time = kwargs.get('last_modified_time', None)
