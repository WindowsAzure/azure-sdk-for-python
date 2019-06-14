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


class IdentityTokenResponse(Model):
    """This is the response from the Identity_GetToken operation.

    :param access_token: This is the requested access token. The app can use
     this token to authenticate to the sink resource.
    :type access_token: str
    :param expires_in: This is how long the access token is valid (in
     seconds).
    :type expires_in: str
    :param expires_on: This is the time when the access token expires. The
     date is represented as the number of seconds from 1970-01-01T0:0:0Z UTC
     until the expiration time. This value is used to determine the lifetime of
     cached tokens.
    :type expires_on: str
    :param ext_expires_in: This indicates the extended lifetime of the token
     (in seconds).
    :type ext_expires_in: str
    :param not_before: This is the time when the access token becomes
     effective. The date is represented as the number of seconds from
     1970-01-01T0:0:0Z UTC until the expiration time.
    :type not_before: str
    :param resource: This is the app ID URI of the sink resource.
    :type resource: str
    :param token_type: This indicates the token type value.
    :type token_type: str
    :param client_id: This is the client_id specified in the request, if any.
    :type client_id: str
    :param object_id: This is the object_id specified in the request, if any.
    :type object_id: str
    :param msi_res_id: This is the msi_res_id specified in the request, if
     any.
    :type msi_res_id: str
    """

    _attribute_map = {
        'access_token': {'key': 'access_token', 'type': 'str'},
        'expires_in': {'key': 'expires_in', 'type': 'str'},
        'expires_on': {'key': 'expires_on', 'type': 'str'},
        'ext_expires_in': {'key': 'ext_expires_in', 'type': 'str'},
        'not_before': {'key': 'not_before', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'token_type': {'key': 'token_type', 'type': 'str'},
        'client_id': {'key': 'client_id', 'type': 'str'},
        'object_id': {'key': 'object_id', 'type': 'str'},
        'msi_res_id': {'key': 'msi_res_id', 'type': 'str'},
    }

    def __init__(self, *, access_token: str=None, expires_in: str=None, expires_on: str=None, ext_expires_in: str=None, not_before: str=None, resource: str=None, token_type: str=None, client_id: str=None, object_id: str=None, msi_res_id: str=None, **kwargs) -> None:
        super(IdentityTokenResponse, self).__init__(**kwargs)
        self.access_token = access_token
        self.expires_in = expires_in
        self.expires_on = expires_on
        self.ext_expires_in = ext_expires_in
        self.not_before = not_before
        self.resource = resource
        self.token_type = token_type
        self.client_id = client_id
        self.object_id = object_id
        self.msi_res_id = msi_res_id
