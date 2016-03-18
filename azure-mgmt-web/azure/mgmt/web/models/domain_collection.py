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


class DomainCollection(Model):
    """
    Collection of domains

    :param value: Collection of resources
    :type value: list of :class:`Domain <azure.mgmt.web.models.Domain>`
    :param next_link: Link to next page of resources
    :type next_link: str
    """ 

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Domain]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self, value=None, next_link=None, **kwargs):
        self.value = value
        self.next_link = next_link
