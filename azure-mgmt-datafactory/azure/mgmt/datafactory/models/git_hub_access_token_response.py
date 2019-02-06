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


class GitHubAccessTokenResponse(Model):
    """Get GitHub access token response definition.

    :param git_hub_access_token: GitHub access token.
    :type git_hub_access_token: str
    """

    _attribute_map = {
        'git_hub_access_token': {'key': 'gitHubAccessToken', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(GitHubAccessTokenResponse, self).__init__(**kwargs)
        self.git_hub_access_token = kwargs.get('git_hub_access_token', None)
