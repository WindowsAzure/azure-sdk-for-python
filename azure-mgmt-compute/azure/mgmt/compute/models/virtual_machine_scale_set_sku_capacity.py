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


class VirtualMachineScaleSetSkuCapacity(Model):
    """
    Describes scaling information of a sku.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar minimum: Gets the minimum capacity.
    :vartype minimum: long
    :ivar maximum: Gets the maximum capacity that can be set.
    :vartype maximum: long
    :ivar default_capacity: Gets the default capacity.
    :vartype default_capacity: long
    :ivar scale_type: Gets the scale type applicable to the sku. Possible
     values include: 'Automatic', 'None'
    :vartype scale_type: str or :class:`VirtualMachineScaleSetSkuScaleType
     <computemanagementclient.models.VirtualMachineScaleSetSkuScaleType>`
    """ 

    _validation = {
        'minimum': {'readonly': True},
        'maximum': {'readonly': True},
        'default_capacity': {'readonly': True},
        'scale_type': {'readonly': True},
    }

    _attribute_map = {
        'minimum': {'key': 'minimum', 'type': 'long'},
        'maximum': {'key': 'maximum', 'type': 'long'},
        'default_capacity': {'key': 'defaultCapacity', 'type': 'long'},
        'scale_type': {'key': 'scaleType', 'type': 'VirtualMachineScaleSetSkuScaleType'},
    }

    def __init__(self):
        self.minimum = None
        self.maximum = None
        self.default_capacity = None
        self.scale_type = None
