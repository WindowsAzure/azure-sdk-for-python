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


class SourceControlCreateOrUpdateParameters(Model):
    """The parameters supplied to the create or update source control operation.

    :param repo_url: The repo url of the source control.
    :type repo_url: str
    :param branch: The repo branch of the source control. Include branch as
     empty string for VsoTfvc.
    :type branch: str
    :param folder_path: The folder path of the source control. Path must be
     relative.
    :type folder_path: str
    :param auto_sync: The auto async of the source control. Default is false.
    :type auto_sync: bool
    :param publish_runbook: The auto publish of the source control. Default is
     true.
    :type publish_runbook: bool
    :param source_type: The source type. Must be one of VsoGit, VsoTfvc,
     GitHub, case sensitive. Possible values include: 'VsoGit', 'VsoTfvc',
     'GitHub'
    :type source_type: str or ~azure.mgmt.automation.models.SourceType
    :param security_token: The authorization token for the repo of the source
     control.
    :type security_token:
     ~azure.mgmt.automation.models.SourceControlSecurityTokenProperties
    :param description: The user description of the source control.
    :type description: str
    """

    _validation = {
        'repo_url': {'max_length': 2000},
        'branch': {'max_length': 255},
        'folder_path': {'max_length': 255},
        'description': {'max_length': 512},
    }

    _attribute_map = {
        'repo_url': {'key': 'properties.repoUrl', 'type': 'str'},
        'branch': {'key': 'properties.branch', 'type': 'str'},
        'folder_path': {'key': 'properties.folderPath', 'type': 'str'},
        'auto_sync': {'key': 'properties.autoSync', 'type': 'bool'},
        'publish_runbook': {'key': 'properties.publishRunbook', 'type': 'bool'},
        'source_type': {'key': 'properties.sourceType', 'type': 'str'},
        'security_token': {'key': 'properties.securityToken', 'type': 'SourceControlSecurityTokenProperties'},
        'description': {'key': 'properties.description', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SourceControlCreateOrUpdateParameters, self).__init__(**kwargs)
        self.repo_url = kwargs.get('repo_url', None)
        self.branch = kwargs.get('branch', None)
        self.folder_path = kwargs.get('folder_path', None)
        self.auto_sync = kwargs.get('auto_sync', None)
        self.publish_runbook = kwargs.get('publish_runbook', None)
        self.source_type = kwargs.get('source_type', None)
        self.security_token = kwargs.get('security_token', None)
        self.description = kwargs.get('description', None)
