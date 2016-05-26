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


class RedisRegenerateKeyParameters(Model):
    """
    Specifies which redis access keys to reset.

    :param key_type: Which redis access key to reset. Possible values
     include: 'Primary', 'Secondary'
    :type key_type: str or :class:`RedisKeyType
     <redismanagementclient.models.RedisKeyType>`
    """ 

    _validation = {
        'key_type': {'required': True},
    }

    _attribute_map = {
        'key_type': {'key': 'keyType', 'type': 'RedisKeyType'},
    }

    def __init__(self, key_type):
        self.key_type = key_type
