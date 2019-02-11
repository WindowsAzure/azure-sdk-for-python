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


class SourceProperties(Model):
    """The properties of the source code repository.

    All required parameters must be populated in order to send to Azure.

    :param source_control_type: Required. The type of source control service.
     Possible values include: 'Github', 'VisualStudioTeamService'
    :type source_control_type: str or
     ~azure.mgmt.containerregistry.v2018_09_01.models.SourceControlType
    :param repository_url: Required. The full URL to the source code
     repository
    :type repository_url: str
    :param branch: The branch name of the source code.
    :type branch: str
    :param source_control_auth_properties: The authorization properties for
     accessing the source code repository and to set up
     webhooks for notifications.
    :type source_control_auth_properties:
     ~azure.mgmt.containerregistry.v2018_09_01.models.AuthInfo
    """

    _validation = {
        'source_control_type': {'required': True},
        'repository_url': {'required': True},
    }

    _attribute_map = {
        'source_control_type': {'key': 'sourceControlType', 'type': 'str'},
        'repository_url': {'key': 'repositoryUrl', 'type': 'str'},
        'branch': {'key': 'branch', 'type': 'str'},
        'source_control_auth_properties': {'key': 'sourceControlAuthProperties', 'type': 'AuthInfo'},
    }

    def __init__(self, *, source_control_type, repository_url: str, branch: str=None, source_control_auth_properties=None, **kwargs) -> None:
        super(SourceProperties, self).__init__(**kwargs)
        self.source_control_type = source_control_type
        self.repository_url = repository_url
        self.branch = branch
        self.source_control_auth_properties = source_control_auth_properties
