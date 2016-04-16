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

from .resource import Resource


class AvailabilitySet(Resource):
    """
    Create or update Availability Set parameters.

    :param id: Resource Id
    :type id: str
    :param name: Resource name
    :type name: str
    :param type: Resource type
    :type type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    :param platform_update_domain_count: Gets or sets Update Domain count.
    :type platform_update_domain_count: int
    :param platform_fault_domain_count: Gets or sets Fault Domain count.
    :type platform_fault_domain_count: int
    :param virtual_machines: Gets or sets a list containing reference to all
     Virtual Machines  created under this Availability Set.
    :type virtual_machines: list of :class:`SubResource
     <computemanagementclient.models.SubResource>`
    :param statuses: Gets or sets the resource status information.
    :type statuses: list of :class:`InstanceViewStatus
     <computemanagementclient.models.InstanceViewStatus>`
    """ 

    _validation = {
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'platform_update_domain_count': {'key': 'properties.platformUpdateDomainCount', 'type': 'int'},
        'platform_fault_domain_count': {'key': 'properties.platformFaultDomainCount', 'type': 'int'},
        'virtual_machines': {'key': 'properties.virtualMachines', 'type': '[SubResource]'},
        'statuses': {'key': 'properties.statuses', 'type': '[InstanceViewStatus]'},
    }

    def __init__(self, location, id=None, name=None, type=None, tags=None, platform_update_domain_count=None, platform_fault_domain_count=None, virtual_machines=None, statuses=None):
        super(AvailabilitySet, self).__init__(id=id, name=name, type=type, location=location, tags=tags)
        self.platform_update_domain_count = platform_update_domain_count
        self.platform_fault_domain_count = platform_fault_domain_count
        self.virtual_machines = virtual_machines
        self.statuses = statuses
