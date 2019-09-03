# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from __future__ import print_function
import functools

from azure.core.exceptions import ResourceNotFoundError
from devtools_testutils import ResourceGroupPreparer
from certificates_preparer import VaultClientPreparer
from certificates_test_case import KeyVaultTestCase


def print(*args):
    assert all(arg is not None for arg in args)


def test_create_certificate_client():
    vault_url = "vault_url"
    # pylint:disable=unused-variable
    # [START create_certificate_client]

    from azure.identity import DefaultAzureCredential
    from azure.keyvault.certificates import CertificateClient

    # Create a CertificateClient using default Azure credentials
    credential = DefaultAzureCredential()
    certificate_client = CertificateClient(vault_url, credential)

    # [END create_certificate_client]


class TestExamplesKeyVault(KeyVaultTestCase):
    @ResourceGroupPreparer()
    @VaultClientPreparer(enable_soft_delete=True)
    def test_example_certificate_crud_operations(self, vault_client, **kwargs):

        certificate_client = vault_client.certificates
        # [START create_certificate]
        from azure.keyvault.certificates import CertificatePolicy, KeyProperties, SecretContentType
        # specify the certificate policy
        cert_policy = CertificatePolicy(key_properties=KeyProperties(exportable=True,
                                                                     key_type='RSA',
                                                                     key_size=2048,
                                                                     reuse_key=False),
                                        content_type=SecretContentType.PFX,
                                        issuer_name='Self',
                                        subject_name='CN=*.microsoft.com',
                                        validity_in_months=24,
                                        san_dns_names=['onedrive.microsoft.com', 'xbox.microsoft.com']
                                        )

        cert_name = "cert-name"
        # create a certificate with optional arguments, returns a long running operation poller
        certificate_operation_poller = certificate_client.create_certificate(name=cert_name, policy=cert_policy)

        # Here we are waiting for the certificate creation operation to be completed
        certificate_operation_poller.wait()

        # You can get the final status of the certificate operation poller using .result()
        print(certificate_operation_poller.result())

        # [END create_certificate]

        # [START get_certificate]

        # get the certificate
        certificate = certificate_client.get_certificate(name=cert_name)

        print(certificate.id)
        print(certificate.name)
        print(certificate.policy.key_properties.exportable)
        print(certificate.policy.key_properties.key_type)
        print(certificate.policy.key_properties.key_size)
        print(certificate.policy.key_properties.reuse_key)
        print(certificate.policy.content_type)
        print(certificate.policy.issuer_name)
        print(certificate.policy.subject_name)
        print(certificate.policy.san_dns_names)
        print(certificate.policy.validity_in_months)

        # [END get_certificate]
        # [START update_certificate]

        # update attributes of an existing certificate
        tags = {"foo": "updated tag"}
        updated_certificate = certificate_client.update_certificate(name=certificate.name, tags=tags)

        print(updated_certificate.version)
        print(updated_certificate.updated)
        print(updated_certificate.tags)

        # [END update_certificate]
        # [START delete_certificate]

        # delete a certificate
        deleted_certificate = certificate_client.delete_certificate(name=certificate.name)

        print(deleted_certificate.name)

        # if the vault has soft-delete enabled, the certificate's deleted date,
        # scheduled purge date, and recovery id are available
        print(deleted_certificate.deleted_date)
        print(deleted_certificate.scheduled_purge_date)
        print(deleted_certificate.recovery_id)

        # [END delete_certificate]

    @ResourceGroupPreparer()
    @VaultClientPreparer(enable_soft_delete=True)
    def test_example_certificate_list_operations(self, vault_client, **kwargs):
        from azure.keyvault.certificates import CertificatePolicy, KeyProperties, SecretContentType
        certificate_client = vault_client.certificates

        # specify the certificate policy
        cert_policy = CertificatePolicy(key_properties=KeyProperties(exportable=True,
                                                                     key_type='RSA',
                                                                     key_size=2048,
                                                                     reuse_key=False),
                                        content_type=SecretContentType.PFX,
                                        issuer_name='Self',
                                        subject_name='CN=*.microsoft.com',
                                        validity_in_months=24,
                                        san_dns_names=['sdk.azure-int.net']
                                        )

        for i in range(4):
            create_certificate_poller = certificate_client.create_certificate(name="certificate{}".format(i), policy=cert_policy)
            create_certificate_poller.wait()

        # [START list_certificates]

        # get an iterator of certificates
        certificates = certificate_client.list_certificates()

        for certificate in certificates:
            print(certificate.id)
            print(certificate.created)
            print(certificate.name)
            print(certificate.updated)
            print(certificate.enabled)

        # [END list_certificates]
        # [START list_certificate_versions]

        # get an iterator of a certificate's versions
        certificate_versions = certificate_client.list_certificate_versions(name="certificate-name")

        for certificate in certificate_versions:
            print(certificate.id)
            print(certificate.updated)
            print(certificate.version)

        # [END list_certificate_versions]
        # [START list_deleted_certificates]

        # get an iterator of deleted certificates (requires soft-delete enabled for the vault)
        deleted_certificates = certificate_client.list_deleted_certificates()

        for certificate in deleted_certificates:
            print(certificate.id)
            print(certificate.name)
            print(certificate.deleted_date)
            print(certificate.scheduled_purge_date)
            print(certificate.deleted_date)

        # [END list_deleted_certificates]

    @ResourceGroupPreparer()
    @VaultClientPreparer()
    def test_example_certificate_backup_restore(self, vault_client, **kwargs):
        from azure.keyvault.certificates import CertificatePolicy, KeyProperties, SecretContentType
        import time
        certificate_client = vault_client.certificates

        # specify the certificate policy
        cert_policy = CertificatePolicy(key_properties=KeyProperties(exportable=True,
                                                                     key_type='RSA',
                                                                     key_size=2048,
                                                                     reuse_key=False),
                                        content_type=SecretContentType.PFX,
                                        issuer_name='Self',
                                        subject_name='CN=*.microsoft.com',
                                        validity_in_months=24,
                                        san_dns_names=['onedrive.microsoft.com', 'xbox.microsoft.com']
                                        )

        cert_name = "cert-name"
        create_certificate_poller = certificate_client.create_certificate(name=cert_name, policy=cert_policy)
        create_certificate_poller.wait()

        # [START backup_certificate]

        # backup certificate
        certificate_backup = certificate_client.backup_certificate(name=cert_name)

        # returns the raw byte sof the backed up certificate
        print(certificate_backup)

        # [END backup_certificate]

        certificate_client.delete_certificate(name=cert_name)

        # [START restore_certificate]

        # restore a certificate backup
        restored_certificate = certificate_client.restore_certificate(backup=certificate_backup)

        print(restored_certificate.id)
        print(restored_certificate.name)
        print(restored_certificate.version)

        # [END restore_certificate]

    @ResourceGroupPreparer()
    @VaultClientPreparer(enable_soft_delete=True)
    def test_example_certificate_recover(self, vault_client, **kwargs):
        from azure.keyvault.certificates import CertificatePolicy, KeyProperties, SecretContentType
        certificate_client = vault_client.certificates

        # specify the certificate policy
        cert_policy = CertificatePolicy(key_properties=KeyProperties(exportable=True,
                                                                     key_type='RSA',
                                                                     key_size=2048,
                                                                     reuse_key=False),
                                        content_type=SecretContentType.PFX,
                                        issuer_name='Self',
                                        subject_name='CN=*.microsoft.com',
                                        validity_in_months=24,
                                        san_dns_names=['onedrive.microsoft.com', 'xbox.microsoft.com']
                                        )

        cert_name = "cert-name"
        create_certificate_poller = certificate_client.create_certificate(name=cert_name, policy=cert_policy)
        create_certificate_poller.wait()
        certificate_client.delete_certificate(name=cert_name)
        self._poll_until_no_exception(
            functools.partial(certificate_client.get_deleted_certificate, cert_name),
            ResourceNotFoundError
        )
        # [START get_deleted_certificate]

        # get a deleted certificate (requires soft-delete enabled for the vault)
        deleted_certificate = certificate_client.get_deleted_certificate(name=cert_name)
        print(deleted_certificate.name)

        # if the vault has soft-delete enabled, the certificate's deleted date,
        # scheduled purge date, and recovery id are available
        print(deleted_certificate.deleted_date)
        print(deleted_certificate.scheduled_purge_date)
        print(deleted_certificate.recovery_id)

        # [END get_deleted_certificate]
        # [START recover_deleted_certificate]

        # recover a deleted certificate to its latest version (requires soft-delete enabled for the vault)
        recovered_certificate = certificate_client.recover_deleted_certificate(name=cert_name)

        print(recovered_certificate.id)
        print(recovered_certificate.name)

        # [END recover_deleted_certificate]
