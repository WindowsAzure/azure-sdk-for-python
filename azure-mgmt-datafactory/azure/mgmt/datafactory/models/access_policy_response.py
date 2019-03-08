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


class AccessPolicyResponse(Model):
    """Get Data Plane read only token response definition.

    :param policy: The user access policy.
    :type policy: ~azure.mgmt.datafactory.models.UserAccessPolicy
    :param access_token: Data Plane read only access token.
    :type access_token: str
    :param data_plane_url: Data Plane service base URL.
    :type data_plane_url: str
    """

    _attribute_map = {
        'policy': {'key': 'policy', 'type': 'UserAccessPolicy'},
        'access_token': {'key': 'accessToken', 'type': 'str'},
        'data_plane_url': {'key': 'dataPlaneUrl', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AccessPolicyResponse, self).__init__(**kwargs)
        self.policy = kwargs.get('policy', None)
        self.access_token = kwargs.get('access_token', None)
        self.data_plane_url = kwargs.get('data_plane_url', None)
