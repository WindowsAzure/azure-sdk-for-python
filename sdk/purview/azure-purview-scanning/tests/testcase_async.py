# coding: utf-8
# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from devtools_testutils import AzureTestCase
from azure.purview.scanning.aio import AzurePurviewScanningClient as AsyncAzurePurviewScanningClient

class PurviewScanningTestAsync(AzureTestCase):

    def create_async_client(self, endpoint):
        credential = self.get_credential(AsyncAzurePurviewScanningClient, is_async=True)
        return self.create_client_from_credential(
            AsyncAzurePurviewScanningClient,
            credential=credential,
            endpoint=endpoint,
        )
