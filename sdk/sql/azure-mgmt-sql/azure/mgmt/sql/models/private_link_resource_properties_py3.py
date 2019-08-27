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


class PrivateLinkResourceProperties(Model):
    """Properties of a private link resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar group_id: The private link resource group id.
    :vartype group_id: str
    :ivar required_members: The private link resource required member names.
    :vartype required_members: list[str]
    """

    _validation = {
        'group_id': {'readonly': True},
        'required_members': {'readonly': True},
    }

    _attribute_map = {
        'group_id': {'key': 'groupId', 'type': 'str'},
        'required_members': {'key': 'requiredMembers', 'type': '[str]'},
    }

    def __init__(self, **kwargs) -> None:
        super(PrivateLinkResourceProperties, self).__init__(**kwargs)
        self.group_id = None
        self.required_members = None
