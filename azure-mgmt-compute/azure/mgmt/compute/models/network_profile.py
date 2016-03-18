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


class NetworkProfile(Model):
    """
    Describes a network profile.

    :param network_interfaces: Gets or sets the network interfaces.
    :type network_interfaces: list of :class:`NetworkInterfaceReference
     <azure.mgmt.compute.models.NetworkInterfaceReference>`
    """ 

    _attribute_map = {
        'network_interfaces': {'key': 'networkInterfaces', 'type': '[NetworkInterfaceReference]'},
    }

    def __init__(self, network_interfaces=None, **kwargs):
        self.network_interfaces = network_interfaces
