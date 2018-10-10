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


class GroupUpdateParameters(Model):
    """Parameters supplied to the Update Group operation.

    :param display_name: Group name.
    :type display_name: str
    :param description: Group description.
    :type description: str
    :param type: Group type. Possible values include: 'custom', 'system',
     'external'
    :type type: str or ~azure.mgmt.apimanagement.models.GroupType
    :param external_id: Identifier of the external groups, this property
     contains the id of the group from the external identity provider, e.g. for
     Azure Active Directory aad://<tenant>.onmicrosoft.com/groups/<group object
     id>; otherwise the value is null.
    :type external_id: str
    """

    _validation = {
        'display_name': {'max_length': 300, 'min_length': 1},
    }

    _attribute_map = {
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'type': {'key': 'properties.type', 'type': 'GroupType'},
        'external_id': {'key': 'properties.externalId', 'type': 'str'},
    }

    def __init__(self, *, display_name: str=None, description: str=None, type=None, external_id: str=None, **kwargs) -> None:
        super(GroupUpdateParameters, self).__init__(**kwargs)
        self.display_name = display_name
        self.description = description
        self.type = type
        self.external_id = external_id
