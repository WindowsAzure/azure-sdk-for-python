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


class SourceControlAuthInfo(Model):
    """The authorization properties for accessing the source code repository.

    All required parameters must be populated in order to send to Azure.

    :param token_type: The type of Auth token. Possible values include: 'PAT',
     'OAuth'
    :type token_type: str or
     ~azure.mgmt.containerregistry.v2018_02_01_preview.models.TokenType
    :param token: Required. The access token used to access the source control
     provider.
    :type token: str
    :param refresh_token: The refresh token used to refresh the access token.
    :type refresh_token: str
    :param scope: The scope of the access token.
    :type scope: str
    :param expires_in: Time in seconds that the token remains valid
    :type expires_in: int
    """

    _validation = {
        'token': {'required': True},
    }

    _attribute_map = {
        'token_type': {'key': 'tokenType', 'type': 'str'},
        'token': {'key': 'token', 'type': 'str'},
        'refresh_token': {'key': 'refreshToken', 'type': 'str'},
        'scope': {'key': 'scope', 'type': 'str'},
        'expires_in': {'key': 'expiresIn', 'type': 'int'},
    }

    def __init__(self, *, token: str, token_type=None, refresh_token: str=None, scope: str=None, expires_in: int=None, **kwargs) -> None:
        super(SourceControlAuthInfo, self).__init__(**kwargs)
        self.token_type = token_type
        self.token = token
        self.refresh_token = refresh_token
        self.scope = scope
        self.expires_in = expires_in
