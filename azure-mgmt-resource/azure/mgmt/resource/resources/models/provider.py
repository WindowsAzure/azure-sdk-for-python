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


class Provider(Model):
    """
    Resource provider information.

    :param id: Gets or sets the provider id.
    :type id: str
    :param namespace: Gets or sets the namespace of the provider.
    :type namespace: str
    :param registration_state: Gets or sets the registration state of the
     provider.
    :type registration_state: str
    :param resource_types: Gets or sets the collection of provider resource
     types.
    :type resource_types: list of :class:`ProviderResourceType
     <azure.mgmt.resource.resources.models.ProviderResourceType>`
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'namespace': {'key': 'namespace', 'type': 'str'},
        'registration_state': {'key': 'registrationState', 'type': 'str'},
        'resource_types': {'key': 'resourceTypes', 'type': '[ProviderResourceType]'},
    }

    def __init__(self, id=None, namespace=None, registration_state=None, resource_types=None, **kwargs):
        self.id = id
        self.namespace = namespace
        self.registration_state = registration_state
        self.resource_types = resource_types
