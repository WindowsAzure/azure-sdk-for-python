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


class PremierAddOnRequest(Model):
    """PremierAddOnRequest

    :param location: Geo region resource belongs to e.g. SouthCentralUS,
     SouthEastAsia
    :type location: str
    :param tags: Tags associated with resource
    :type tags: dict
    :param plan: Azure resource manager plan
    :type plan: :class:`ArmPlan <websitemanagementclient.models.ArmPlan>`
    :param properties: Resource specific properties
    :type properties: object
    :param sku: Sku description of the resource
    :type sku: :class:`SkuDescription
     <websitemanagementclient.models.SkuDescription>`
    """ 

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'plan': {'key': 'plan', 'type': 'ArmPlan'},
        'properties': {'key': 'properties', 'type': 'object'},
        'sku': {'key': 'sku', 'type': 'SkuDescription'},
    }

    def __init__(self, location=None, tags=None, plan=None, properties=None, sku=None):
        self.location = location
        self.tags = tags
        self.plan = plan
        self.properties = properties
        self.sku = sku
