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


class OAuth2AuthenticationSettingsContract(Model):
    """API OAuth2 Authentication settings details.

    :param authorization_server_id: OAuth authorization server identifier.
    :type authorization_server_id: str
    :param scope: operations scope.
    :type scope: str
    """

    _attribute_map = {
        'authorization_server_id': {'key': 'authorizationServerId', 'type': 'str'},
        'scope': {'key': 'scope', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OAuth2AuthenticationSettingsContract, self).__init__(**kwargs)
        self.authorization_server_id = kwargs.get('authorization_server_id', None)
        self.scope = kwargs.get('scope', None)
