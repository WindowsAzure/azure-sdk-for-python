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

from .tracked_resource import TrackedResource


class Profile(TrackedResource):
    """
    CDN profile represents the top level resource and the entry point into the
    CDN API. This allows users to set up a logical grouping of endpoints in
    addition to creating shared configuration settings and selecting pricing
    tiers and providers.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    :param sku: The SKU (pricing tier) of the CDN profile.
    :type sku: :class:`Sku <azure.mgmt.cdn.models.Sku>`
    :ivar resource_state: Resource status of the profile. Possible values
     include: 'Creating', 'Active', 'Deleting', 'Disabled'
    :vartype resource_state: str or :class:`ProfileResourceState
     <cdnmanagementclient.models.ProfileResourceState>`
    :param provisioning_state: Provisioning status of the profile. Possible
     values include: 'Creating', 'Succeeded', 'Failed'
    :type provisioning_state: str or :class:`ProvisioningState
     <cdnmanagementclient.models.ProvisioningState>`
    """ 

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'tags': {'required': True},
        'resource_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'properties.sku', 'type': 'Sku'},
        'resource_state': {'key': 'properties.resourceState', 'type': 'ProfileResourceState'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'ProvisioningState'},
    }

    def __init__(self, location, tags, sku=None, provisioning_state=None):
        super(Profile, self).__init__(location=location, tags=tags)
        self.sku = sku
        self.resource_state = None
        self.provisioning_state = provisioning_state
