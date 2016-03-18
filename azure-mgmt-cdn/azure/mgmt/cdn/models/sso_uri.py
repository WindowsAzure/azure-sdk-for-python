# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class SsoUri(Model):
    """
    Sso uri required to login to third party web portal

    :param sso_uri_value: The uri used to login to third party web portal
    :type sso_uri_value: str
    """ 

    _attribute_map = {
        'sso_uri_value': {'key': 'ssoUriValue', 'type': 'str'},
    }

    def __init__(self, sso_uri_value=None, **kwargs):
        self.sso_uri_value = sso_uri_value
