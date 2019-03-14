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


class FactoryRepoConfiguration(Model):
    """Factory's git repo information.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: FactoryVSTSConfiguration, FactoryGitHubConfiguration

    All required parameters must be populated in order to send to Azure.

    :param account_name: Required. Account name.
    :type account_name: str
    :param repository_name: Required. Repository name.
    :type repository_name: str
    :param collaboration_branch: Required. Collaboration branch.
    :type collaboration_branch: str
    :param root_folder: Required. Root folder.
    :type root_folder: str
    :param last_commit_id: Last commit id.
    :type last_commit_id: str
    :param type: Required. Constant filled by server.
    :type type: str
    """

    _validation = {
        'account_name': {'required': True},
        'repository_name': {'required': True},
        'collaboration_branch': {'required': True},
        'root_folder': {'required': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'account_name': {'key': 'accountName', 'type': 'str'},
        'repository_name': {'key': 'repositoryName', 'type': 'str'},
        'collaboration_branch': {'key': 'collaborationBranch', 'type': 'str'},
        'root_folder': {'key': 'rootFolder', 'type': 'str'},
        'last_commit_id': {'key': 'lastCommitId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    _subtype_map = {
        'type': {'FactoryVSTSConfiguration': 'FactoryVSTSConfiguration', 'FactoryGitHubConfiguration': 'FactoryGitHubConfiguration'}
    }

    def __init__(self, **kwargs):
        super(FactoryRepoConfiguration, self).__init__(**kwargs)
        self.account_name = kwargs.get('account_name', None)
        self.repository_name = kwargs.get('repository_name', None)
        self.collaboration_branch = kwargs.get('collaboration_branch', None)
        self.root_folder = kwargs.get('root_folder', None)
        self.last_commit_id = kwargs.get('last_commit_id', None)
        self.type = None
