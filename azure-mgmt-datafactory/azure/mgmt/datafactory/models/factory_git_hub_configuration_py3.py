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

from .factory_repo_configuration_py3 import FactoryRepoConfiguration


class FactoryGitHubConfiguration(FactoryRepoConfiguration):
    """Factory's GitHub repo information.

    All required parameters must be populated in order to send to Azure.

    :param account_name: Required. Account name.
    :type account_name: str
    :param repository_name: Required. Rrepository name.
    :type repository_name: str
    :param collaboration_branch: Required. Collaboration branch.
    :type collaboration_branch: str
    :param root_folder: Required. Root folder.
    :type root_folder: str
    :param last_commit_id: Last commit id.
    :type last_commit_id: str
    :param type: Required. Constant filled by server.
    :type type: str
    :param host_name: GitHub Enterprise host name. For example:
     https://github.mydomain.com
    :type host_name: str
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
        'host_name': {'key': 'hostName', 'type': 'str'},
    }

    def __init__(self, *, account_name: str, repository_name: str, collaboration_branch: str, root_folder: str, last_commit_id: str=None, host_name: str=None, **kwargs) -> None:
        super(FactoryGitHubConfiguration, self).__init__(account_name=account_name, repository_name=repository_name, collaboration_branch=collaboration_branch, root_folder=root_folder, last_commit_id=last_commit_id, **kwargs)
        self.host_name = host_name
        self.type = 'FactoryGitHubConfiguration'
