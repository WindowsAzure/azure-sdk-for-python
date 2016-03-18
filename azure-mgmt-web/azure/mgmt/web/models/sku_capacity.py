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


class SkuCapacity(Model):
    """
    Description of the App Service Plan scale options

    :param minimum: Minimum number of Workers for this App Service Plan SKU
    :type minimum: int
    :param maximum: Maximum number of Workers for this App Service Plan SKU
    :type maximum: int
    :param default: Default number of Workers for this App Service Plan SKU
    :type default: int
    :param scale_type: Available scale configurations for an App Service Plan
    :type scale_type: str
    """ 

    _attribute_map = {
        'minimum': {'key': 'minimum', 'type': 'int'},
        'maximum': {'key': 'maximum', 'type': 'int'},
        'default': {'key': 'default', 'type': 'int'},
        'scale_type': {'key': 'scaleType', 'type': 'str'},
    }

    def __init__(self, minimum=None, maximum=None, default=None, scale_type=None, **kwargs):
        self.minimum = minimum
        self.maximum = maximum
        self.default = default
        self.scale_type = scale_type
