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


class USqlDirectedColumn(Model):
    """
    A Data Lake Analytics catalog U-SQL directed column item.

    :param name: the name of the index in the table.
    :type name: str
    :param descending: the switch indicating if the index is descending or
     not.
    :type descending: bool
    """ 

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'descending': {'key': 'descending', 'type': 'bool'},
    }

    def __init__(self, name=None, descending=None):
        self.name = name
        self.descending = descending
