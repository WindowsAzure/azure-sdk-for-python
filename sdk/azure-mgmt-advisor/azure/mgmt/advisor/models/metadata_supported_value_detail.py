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


class MetadataSupportedValueDetail(Model):
    """The metadata supported value detail.

    :param id: The id.
    :type id: str
    :param display_name: The display name.
    :type display_name: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(MetadataSupportedValueDetail, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.display_name = kwargs.get('display_name', None)
