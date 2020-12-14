# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import uuid

from azure_devtools.perfstress_tests import RandomStream

from ._test_base_legacy import _LegacyContainerTest


class LegacyUploadTest(_LegacyContainerTest):
    def __init__(self, arguments):
        super().__init__(arguments)
        self.blob_name = "blobtest-" + str(uuid.uuid4())

    def run_sync(self):
        data = RandomStream(self.args.size)
        self.service_client.create_blob_from_stream(
            container_name=self.container_name,
            blob_name=self.blob_name,
            stream=data,
            max_connections=self.args.max_concurrency)

    async def run_async(self):
        raise NotImplementedError("Async not supported for legacy T1 tests.")
