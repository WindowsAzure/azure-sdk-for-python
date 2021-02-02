# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import asyncio

from azure_devtools.scenario_tests.patches import mock_in_unit_test
from devtools_testutils import AzureTestCase

from azure.keyvault.keys import KeyClient


def skip_sleep(unit_test):
    async def immediate_return(_):
        return

    return mock_in_unit_test(unit_test, "asyncio.sleep", immediate_return)


class KeyVaultTestCase(AzureTestCase):
    def __init__(self, *args, match_body=True, **kwargs):
        super().__init__(*args, match_body=match_body, **kwargs)
        self.replay_patches.append(skip_sleep)

    def setUp(self):
        self.list_test_size = 7
        super(KeyVaultTestCase, self).setUp()

    def create_kv_client(self, vault_uri, **kwargs):
        credential = self.get_credential(KeyClient)
        return self.create_client_from_credential(
            KeyClient, credential=credential, vault_url=vault_uri, **kwargs
        )

    def get_resource_name(self, name):
        """helper to create resources with a consistent, test-indicative prefix"""
        return super(KeyVaultTestCase, self).get_resource_name("livekvtest{}".format(name))

    async def _poll_until_no_exception(self, fn, expected_exception, max_retries=20, retry_delay=3):
        """polling helper for live tests because some operations take an unpredictable amount of time to complete"""

        for i in range(max_retries):
            try:
                return await fn()
            except expected_exception:
                if i == max_retries - 1:
                    raise
                if self.is_live:
                    await asyncio.sleep(retry_delay)

    async def _poll_until_exception(self, fn, expected_exception, max_retries=20, retry_delay=3):
        """polling helper for live tests because some operations take an unpredictable amount of time to complete"""

        for _ in range(max_retries):
            try:
                await fn()
                if self.is_live:
                    await asyncio.sleep(retry_delay)
            except expected_exception:
                return
        self.fail("expected exception {expected_exception} was not raised")
