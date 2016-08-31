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


class SsoUri(Model):
    """SSO URI required to login to third party web portal.

    :param sso_uri_value: The URI used to login to third party web portal.
    :type sso_uri_value: str
    """ 

    _attribute_map = {
        'sso_uri_value': {'key': 'ssoUriValue', 'type': 'str'},
    }

    def __init__(self, sso_uri_value=None):
        self.sso_uri_value = sso_uri_value
