# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ResourceGroupFilter(Model):
    """Resource group filter.

    :param tag_name: Gets or sets the tag name.
    :type tag_name: str
    :param tag_value: Gets or sets the tag value.
    :type tag_value: str
    """ 

    _attribute_map = {
        'tag_name': {'key': 'tagName', 'type': 'str'},
        'tag_value': {'key': 'tagValue', 'type': 'str'},
    }

    def __init__(self, tag_name=None, tag_value=None):
        self.tag_name = tag_name
        self.tag_value = tag_value
