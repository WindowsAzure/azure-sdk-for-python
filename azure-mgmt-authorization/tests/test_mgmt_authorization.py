﻿# coding: utf-8

#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#--------------------------------------------------------------------------
import unittest

import azure.mgmt.authorization
from devtools_testutils import AzureMgmtTestCase, ResourceGroupPreparer

class MgmtAuthorizationTest(AzureMgmtTestCase):

    def setUp(self):
        super(MgmtAuthorizationTest, self).setUp()
        self.authorization_client = self.create_mgmt_client(
            azure.mgmt.authorization.AuthorizationManagementClient
        )

    @ResourceGroupPreparer()
    def test_authorization(self, resource_group, location):
        permissions = self.authorization_client.permissions.list_for_resource_group(
            resource_group.name
        )

        permissions = list(permissions)
        self.assertEqual(len(permissions), 1)
        self.assertEqual(permissions[0].actions[0], '*')

    @ResourceGroupPreparer()
    def test_role_definitions(self, resource_group, location):
        # Get "Contributor" built-in role as a RoleDefinition object
        role_name = 'Contributor'
        roles = list(self.authorization_client.role_definitions.list(
            resource_group.id,
            filter="roleName eq '{}'".format(role_name)
        ))
        assert len(roles) == 1

#------------------------------------------------------------------------------
if __name__ == '__main__':
    unittest.main()
