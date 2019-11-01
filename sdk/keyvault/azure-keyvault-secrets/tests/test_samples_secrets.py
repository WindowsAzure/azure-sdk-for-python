# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# -------------------------------------
from __future__ import print_function
import functools
import hashlib
import os

from azure.core.exceptions import ResourceNotFoundError
from devtools_testutils import ResourceGroupPreparer
from secrets_preparer import VaultClientPreparer
from secrets_test_case import KeyVaultTestCase


def print(*args):
    assert all(arg is not None for arg in args)


def test_create_secret_client():
    vault_url = "vault_url"
    # pylint:disable=unused-variable
    # [START create_secret_client]

    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    # Create a SecretClient using default Azure credentials
    credentials = DefaultAzureCredential()
    secret_client = SecretClient(vault_url, credentials)

    # [END create_secret_client]


class TestExamplesKeyVault(KeyVaultTestCase):

    # incorporate md5 hashing of run identifier into resource group name for uniqueness
    name_prefix = "kv-test-" + hashlib.md5(os.environ['RUN_IDENTIFIER'].encode()).hexdigest()[-3:]

    @ResourceGroupPreparer(name_prefix=name_prefix)
    @VaultClientPreparer(enable_soft_delete=True)
    def test_example_secret_crud_operations(self, vault_client, **kwargs):
        secret_client = vault_client.secrets

        # [START set_secret]
        from dateutil import parser as date_parse

        expires_on = date_parse.parse("2050-02-02T08:00:00.000Z")

        # create a secret, setting optional arguments
        secret = secret_client.set_secret("secret-name", "secret-value", expires_on=expires_on)

        print(secret.name)
        print(secret.properties.version)
        print(secret.properties.expires_on)

        # [END set_secret]
        # [START get_secret]

        # get the latest version of a secret
        secret = secret_client.get_secret("secret-name")

        # alternatively, specify a version
        secret = secret_client.get_secret("secret-name", secret.properties.version)

        print(secret.id)
        print(secret.name)
        print(secret.properties.version)
        print(secret.properties.vault_url)

        # [END get_secret]
        # [START update_secret]

        # update attributes of an existing secret

        content_type = "text/plain"
        tags = {"foo": "updated tag"}
        updated_secret_properties = secret_client.update_secret_properties(
            "secret-name", content_type=content_type, tags=tags
        )

        print(updated_secret_properties.version)
        print(updated_secret_properties.updated_on)
        print(updated_secret_properties.content_type)
        print(updated_secret_properties.tags)

        # [END update_secret]
        # [START delete_secret]

        # delete a secret
        deleted_secret_poller = secret_client.begin_delete_secret("secret-name")
        deleted_secret = deleted_secret_poller.result()

        print(deleted_secret.name)

        # if the vault has soft-delete enabled, the secret's, deleted_date
        # scheduled purge date and recovery id are set
        print(deleted_secret.deleted_date)
        print(deleted_secret.scheduled_purge_date)
        print(deleted_secret.recovery_id)

        # if you want to block until secret is deleted server-side, call wait() on the poller
        deleted_secret_poller.wait()

        # [END delete_secret]

    @ResourceGroupPreparer(name_prefix=name_prefix)
    @VaultClientPreparer(enable_soft_delete=True)
    def test_example_secret_list_operations(self, vault_client, **kwargs):
        secret_client = vault_client.secrets

        for i in range(7):
            secret_client.set_secret("key{}".format(i), "value{}".format(i))

        # [START list_secrets]

        # list secrets
        secrets = secret_client.list_properties_of_secrets()

        for secret in secrets:
            # the list doesn't include values or versions of the secrets
            print(secret.id)
            print(secret.name)
            print(secret.enabled)

        # [END list_secrets]

        # pylint: disable=unused-variable

        # [START list_properties_of_secret_versions]
        secret_versions = secret_client.list_properties_of_secret_versions("secret-name")

        for secret in secrets:
            # the list doesn't include the values at each version
            print(secret.id)
            print(secret.enabled)
            print(secret.updated_on)

        # [END list_properties_of_secret_versions]
        # [START list_deleted_secrets]

        # gets an iterator of deleted secrets (requires soft-delete enabled for the vault)
        deleted_secrets = secret_client.list_deleted_secrets()

        for secret in deleted_secrets:
            # the list doesn't include values or versions of the deleted secrets
            print(secret.id)
            print(secret.name)
            print(secret.scheduled_purge_date)
            print(secret.recovery_id)
            print(secret.deleted_date)

        # [END list_deleted_secrets]

    @ResourceGroupPreparer(name_prefix=name_prefix)
    @VaultClientPreparer()
    def test_example_secrets_backup_restore(self, vault_client, **kwargs):
        secret_client = vault_client.secrets
        created_secret = secret_client.set_secret("secret-name", "secret-value")
        secret_name = created_secret.name
        # [START backup_secret]
        # backup secret
        # returns the raw bytes of the backed up secret
        secret_backup = secret_client.backup_secret("secret-name")

        print(secret_backup)

        # [END backup_secret]
        polling_interval = 0 if self.is_playback() else 2
        secret_client.begin_delete_secret("secret-name", _polling_interval=polling_interval).wait()
        # [START restore_secret_backup]

        # restores a backed up secret
        restored_secret = secret_client.restore_secret_backup(secret_backup)
        print(restored_secret.id)
        print(restored_secret.version)

        # [END restore_secret_backup]

    @ResourceGroupPreparer(name_prefix=name_prefix)
    @VaultClientPreparer(enable_soft_delete=True)
    def test_example_secrets_recover(self, vault_client, **kwargs):
        secret_client = vault_client.secrets
        created_secret = secret_client.set_secret("secret-name", "secret-value")
        polling_interval = 0 if self.is_playback() else 2
        secret_client.begin_delete_secret(created_secret.name, _polling_interval=polling_interval).wait()

        # [START get_deleted_secret]
        # gets a deleted secret (requires soft-delete enabled for the vault)
        deleted_secret = secret_client.get_deleted_secret("secret-name")
        print(deleted_secret.name)

        # [END get_deleted_secret]
        # [START recover_deleted_secret]

        # recover deleted secret to the latest version
        recover_secret_poller = secret_client.begin_recover_deleted_secret("secret-name")
        recovered_secret = recover_secret_poller.result()
        print(recovered_secret.id)
        print(recovered_secret.name)

        # if you want to block until secret is recovered server-side, call wait() on the poller
        recover_secret_poller.wait()

        # [END recover_deleted_secret]
