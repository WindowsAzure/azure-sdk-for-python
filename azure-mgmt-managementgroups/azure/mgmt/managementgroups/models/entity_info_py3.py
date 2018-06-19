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


class EntityInfo(Model):
    """The entity.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The fully qualified ID for the entity.  For example,
     /providers/Microsoft.Management/managementGroups/0000000-0000-0000-0000-000000000000
    :vartype id: str
    :ivar type: The type of the resource. For example,
     /providers/Microsoft.Management/managementGroups
    :vartype type: str
    :ivar name: The name of the entity. For example,
     00000000-0000-0000-0000-000000000000
    :vartype name: str
    :param tenant_id: The AAD Tenant ID associated with the entity. For
     example, 00000000-0000-0000-0000-000000000000
    :type tenant_id: str
    :param display_name: The friendly name of the management group.
    :type display_name: str
    :param parent: Parent.
    :type parent: ~azure.mgmt.managementgroups.models.EntityParentGroupInfo
    :param permissions: Permissions. Possible values include: 'noaccess',
     'view', 'edit', 'delete'
    :type permissions: str or ~azure.mgmt.managementgroups.models.enum
    :param inherited_permissions: Inherited Permissions. Possible values
     include: 'noaccess', 'view', 'edit', 'delete'
    :type inherited_permissions: str or
     ~azure.mgmt.managementgroups.models.enum
    :param number_of_descendants: Number of Descendants.
    :type number_of_descendants: int
    :param number_of_children: Number of Children. Number of children is the
     number of Groups and Subscriptions that are exactly one level underneath
     the current Group.
    :type number_of_children: int
    :param number_of_child_groups: Number of Child Groups. Number of children
     is the number of Groups that are exactly one level underneath the current
     Group.
    :type number_of_child_groups: int
    :param parent_display_name_chain: The parent display name chain from the
     root group to the immediate parent
    :type parent_display_name_chain: list[str]
    :param parent_name_chain: The parent name chain from the root group to the
     immediate parent
    :type parent_name_chain: list[str]
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'tenant_id': {'key': 'properties.tenantId', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'parent': {'key': 'properties.parent', 'type': 'EntityParentGroupInfo'},
        'permissions': {'key': 'properties.permissions', 'type': 'str'},
        'inherited_permissions': {'key': 'properties.inheritedPermissions', 'type': 'str'},
        'number_of_descendants': {'key': 'properties.numberOfDescendants', 'type': 'int'},
        'number_of_children': {'key': 'properties.numberOfChildren', 'type': 'int'},
        'number_of_child_groups': {'key': 'properties.numberOfChildGroups', 'type': 'int'},
        'parent_display_name_chain': {'key': 'properties.parentDisplayNameChain', 'type': '[str]'},
        'parent_name_chain': {'key': 'properties.parentNameChain', 'type': '[str]'},
    }

    def __init__(self, *, tenant_id: str=None, display_name: str=None, parent=None, permissions=None, inherited_permissions=None, number_of_descendants: int=None, number_of_children: int=None, number_of_child_groups: int=None, parent_display_name_chain=None, parent_name_chain=None, **kwargs) -> None:
        super(EntityInfo, self).__init__(**kwargs)
        self.id = None
        self.type = None
        self.name = None
        self.tenant_id = tenant_id
        self.display_name = display_name
        self.parent = parent
        self.permissions = permissions
        self.inherited_permissions = inherited_permissions
        self.number_of_descendants = number_of_descendants
        self.number_of_children = number_of_children
        self.number_of_child_groups = number_of_child_groups
        self.parent_display_name_chain = parent_display_name_chain
        self.parent_name_chain = parent_name_chain
