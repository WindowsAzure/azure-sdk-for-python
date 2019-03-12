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


class Acl(Model):
    """A Data Lake Analytics catalog access control list (ACL) entry.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar ace_type: the access control list (ACL) entry type. UserObj and
     GroupObj denote the owning user and group, respectively. Possible values
     include: 'UserObj', 'GroupObj', 'Other', 'User', 'Group'
    :vartype ace_type: str or
     ~azure.mgmt.datalake.analytics.catalog.models.AclType
    :ivar principal_id: the Azure AD object ID of the user or group being
     specified in the access control list (ACL) entry.
    :vartype principal_id: str
    :ivar permission: the permission type of the access control list (ACL)
     entry. Possible values include: 'None', 'Use', 'Create', 'Drop', 'Alter',
     'Write', 'All'
    :vartype permission: str or
     ~azure.mgmt.datalake.analytics.catalog.models.PermissionType
    """

    _validation = {
        'ace_type': {'readonly': True},
        'principal_id': {'readonly': True},
        'permission': {'readonly': True},
    }

    _attribute_map = {
        'ace_type': {'key': 'aceType', 'type': 'str'},
        'principal_id': {'key': 'principalId', 'type': 'str'},
        'permission': {'key': 'permission', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(Acl, self).__init__(**kwargs)
        self.ace_type = None
        self.principal_id = None
        self.permission = None
