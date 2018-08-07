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


class EntityParentGroupInfo(Model):
    """(Optional) The ID of the parent management group.

    :param id: The fully qualified ID for the parent management group.  For
     example,
     /providers/Microsoft.Management/managementGroups/0000000-0000-0000-0000-000000000000
    :type id: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, **kwargs) -> None:
        super(EntityParentGroupInfo, self).__init__(**kwargs)
        self.id = id
