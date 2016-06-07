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


class Sku(Model):
    """
    The SKU (pricing tier) of the CDN profile.

    :param name: Name of the pricing tier. Possible values include:
     'Standard_Verizon', 'Premium_Verizon', 'Custom_Verizon',
     'Standard_Akamai'
    :type name: str or :class:`SkuName <azure.mgmt.cdn.models.SkuName>`
    """ 

    _attribute_map = {
        'name': {'key': 'name', 'type': 'SkuName'},
    }

    def __init__(self, name=None):
        self.name = name
