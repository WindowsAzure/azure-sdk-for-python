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


class BaiduCredentialProperties(Model):
    """Description of a NotificationHub BaiduCredential.

    :param baidu_api_key: Get or Set Baidu Api Key.
    :type baidu_api_key: str
    :param baidu_end_point: Get or Set Baidu Endpoint.
    :type baidu_end_point: str
    :param baidu_secret_key: Get or Set Baidu Secret Key
    :type baidu_secret_key: str
    """ 

    _attribute_map = {
        'baidu_api_key': {'key': 'baiduApiKey', 'type': 'str'},
        'baidu_end_point': {'key': 'baiduEndPoint', 'type': 'str'},
        'baidu_secret_key': {'key': 'baiduSecretKey', 'type': 'str'},
    }

    def __init__(self, baidu_api_key=None, baidu_end_point=None, baidu_secret_key=None):
        self.baidu_api_key = baidu_api_key
        self.baidu_end_point = baidu_end_point
        self.baidu_secret_key = baidu_secret_key
