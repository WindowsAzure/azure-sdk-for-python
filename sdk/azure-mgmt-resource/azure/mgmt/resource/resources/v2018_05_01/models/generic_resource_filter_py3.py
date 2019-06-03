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


class GenericResourceFilter(Model):
    """Resource filter.

    :param resource_type: The resource type.
    :type resource_type: str
    :param tagname: The tag name.
    :type tagname: str
    :param tagvalue: The tag value.
    :type tagvalue: str
    """

    _attribute_map = {
        'resource_type': {'key': 'resourceType', 'type': 'str'},
        'tagname': {'key': 'tagname', 'type': 'str'},
        'tagvalue': {'key': 'tagvalue', 'type': 'str'},
    }

    def __init__(self, *, resource_type: str=None, tagname: str=None, tagvalue: str=None, **kwargs) -> None:
        super(GenericResourceFilter, self).__init__(**kwargs)
        self.resource_type = resource_type
        self.tagname = tagname
        self.tagvalue = tagvalue
