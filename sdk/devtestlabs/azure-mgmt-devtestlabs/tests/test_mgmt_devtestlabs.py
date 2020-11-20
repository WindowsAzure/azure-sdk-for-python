﻿# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import unittest

import azure.mgmt.devtestlabs
from devtools_testutils import AzureMgmtTestCase, ResourceGroupPreparer


class MgmtDevTestLabsTest(AzureMgmtTestCase):

    def setUp(self):
        super(MgmtDevTestLabsTest, self).setUp()
        self.client = self.create_mgmt_client(
            azure.mgmt.devtestlabs.DevTestLabsClient
        )

    @ResourceGroupPreparer()
    def test_devtestlabs(self, resource_group, location):
        lab_name = self.get_resource_name('pylab')

        async_lab = self.client.labs.begin_create_or_update(
            resource_group.name,
            lab_name,
            {'location': location}
        )
        lab = async_lab.result()
        self.assertEqual(lab.name, lab_name)

        # get
        self.client.labs.get(resource_group.name, lab_name)

        # update
        BODY = {
            "properties": {
                "labStorageType": "Premium"
            }
        }
        self.client.labs.update(resource_group.name, lab_name, BODY)

        # delete
        result = self.client.labs.begin_delete(resource_group.name, lab_name)
        result.result()


# ------------------------------------------------------------------------------
if __name__ == '__main__':
    unittest.main()
