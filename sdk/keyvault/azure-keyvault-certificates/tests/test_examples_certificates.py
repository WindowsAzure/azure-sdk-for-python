# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from __future__ import print_function
import functools
import hashlib
import os

from devtools_testutils import ResourceGroupPreparer
from certificates_preparer import VaultClientPreparer
from certificates_test_case import KeyVaultTestCase
from azure.keyvault.certificates import CertificatePolicy, CertificateContentType, WellKnownIssuerNames


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
    certificate_client = CertificateClient(vault_url=vault_url, credential=credential)

    # [END create_certificate_client]


class TestExamplesKeyVault(KeyVaultTestCase):

    # incorporate md5 hashing of run identifier into resource group name for uniqueness
    name_prefix = "kv-test-" + hashlib.md5(os.environ["RUN_IDENTIFIER"].encode()).hexdigest()[-3:]

    @ResourceGroupPreparer(name_prefix=name_prefix)
    @VaultClientPreparer(enable_soft_delete=True)
    def test_example_certificate_crud_operations(self, vault_client, **kwargs):
        certificate_client = vault_client.certificates

        # [START create_certificate]
        from azure.keyvault.certificates import CertificatePolicy, CertificateContentType, WellKnownIssuerNames

        # specify the certificate policy
        cert_policy = CertificatePolicy(
            issuer_name=WellKnownIssuerNames.Self,
            subject="CN=*.microsoft.com",
            san_dns_names=["sdk.azure-int.net"],
            exportable=True,
            key_type="RSA",
            key_size=2048,
            reuse_key=False,
            content_type=CertificateContentType.PKCS12,
            validity_in_months=24,
        )

        cert_name = "cert-name"
        # create a certificate with optional arguments, returns a long running operation poller
        certificate_operation_poller = certificate_client.begin_create_certificate(
            certificate_name=cert_name, policy=cert_policy
        )

        # Here we are waiting for the certificate creation operation to be completed
        certificate = certificate_operation_poller.result()

        # You can get the final status of the certificate operation poller using .result()
        print(certificate_operation_poller.result())

        print(certificate.id)
        print(certificate.name)
        print(certificate.policy.issuer_name)

        # [END create_certificate]

        # [START get_certificate]

        # get the certificate
        certificate = certificate_client.get_certificate(cert_name)

        print(certificate.id)
        print(certificate.name)
        print(certificate.policy.issuer_name)

        # [END get_certificate]
        # [START update_certificate]

        # update attributes of an existing certificate
        tags = {"foo": "updated tag"}
        updated_certificate = certificate_client.update_certificate_properties(
            certificate_name=certificate.name, tags=tags
        )

        print(updated_certificate.properties.version)
        print(updated_certificate.properties.updated_on)
        print(updated_certificate.properties.tags)

        # [END update_certificate]
        # [START delete_certificate]

        # delete a certificate
        deleted_certificate = certificate_client.begin_delete_certificate(certificate.name).result()

        print(deleted_certificate.name)

        # if the vault has soft-delete enabled, the certificate's deleted date,
        # scheduled purge date, and recovery id are available
        print(deleted_certificate.deleted_on)
        print(deleted_certificate.scheduled_purge_date)
        print(deleted_certificate.recovery_id)

        # [END delete_certificate]

    @ResourceGroupPreparer(name_prefix=name_prefix)
    @VaultClientPreparer(enable_soft_delete=True)
    def test_example_certificate_list_operations(self, vault_client, **kwargs):
        certificate_client = vault_client.certificates

        # specify the certificate policy
        cert_policy = CertificatePolicy(
            issuer_name=WellKnownIssuerNames.Self,
            subject="CN=*.microsoft.com",
            san_dns_names=["sdk.azure-int.net"],
            exportable=True,
            key_type="RSA",
            key_size=2048,
            reuse_key=False,
            content_type=CertificateContentType.PKCS12,
            validity_in_months=24,
        )

        polling_interval = 0 if self.is_playback() else None

        for i in range(4):
            certificate_client.begin_create_certificate(
                certificate_name="certificate{}".format(i),
                policy=cert_policy,
                _polling_interval=polling_interval
            ).wait()

        # [START list_properties_of_certificates]

        # get an iterator of certificates
        certificates = certificate_client.list_properties_of_certificates()

        for certificate in certificates:
            print(certificate.id)
            print(certificate.created_on)
            print(certificate.name)
            print(certificate.updated_on)
            print(certificate.enabled)

        # [END list_properties_of_certificates]
        # [START list_properties_of_certificate_versions]

        # get an iterator of a certificate's versions
        certificate_versions = certificate_client.list_properties_of_certificate_versions("certificate-name")

        for certificate in certificate_versions:
            print(certificate.id)
            print(certificate.updated_on)
            print(certificate.version)

        # [END list_properties_of_certificate_versions]
        # [START list_deleted_certificates]

        # get an iterator of deleted certificates (requires soft-delete enabled for the vault)
        deleted_certificates = certificate_client.list_deleted_certificates()

        for certificate in deleted_certificates:
            print(certificate.id)
            print(certificate.name)
            print(certificate.deleted_on)
            print(certificate.scheduled_purge_date)
            print(certificate.deleted_on)

        # [END list_deleted_certificates]

    @ResourceGroupPreparer(name_prefix=name_prefix)
    @VaultClientPreparer()
    def test_example_certificate_backup_restore(self, vault_client, **kwargs):
        certificate_client = vault_client.certificates

        # specify the certificate policy
        cert_policy = CertificatePolicy(
            issuer_name=WellKnownIssuerNames.Self,
            subject="CN=*.microsoft.com",
            san_dns_names=["sdk.azure-int.net"],
            exportable=True,
            key_type="RSA",
            key_size=2048,
            reuse_key=False,
            content_type=CertificateContentType.PKCS12,
            validity_in_months=24,
        )
        polling_interval = 0 if self.is_playback() else None
        cert_name = "cert-name"
        certificate_client.begin_create_certificate(
            certificate_name=cert_name, policy=cert_policy, _polling_interval=polling_interval
        ).wait()

        # [START backup_certificate]

        # backup certificate
        certificate_backup = certificate_client.backup_certificate(cert_name)

        # returns the raw bytes of the backed up certificate
        print(certificate_backup)

        # [END backup_certificate]

        certificate_client.begin_delete_certificate(
            certificate_name=cert_name, _polling_interval=polling_interval
        ).wait()

        # [START restore_certificate]

        # restore a certificate backup
        restored_certificate = certificate_client.restore_certificate_backup(certificate_backup)

        print(restored_certificate.id)
        print(restored_certificate.name)
        print(restored_certificate.properties.version)

        # [END restore_certificate]

    @ResourceGroupPreparer(name_prefix=name_prefix)
    @VaultClientPreparer(enable_soft_delete=True)
    def test_example_certificate_recover(self, vault_client, **kwargs):
        certificate_client = vault_client.certificates

        # specify the certificate policy
        cert_policy = CertificatePolicy(
            issuer_name=WellKnownIssuerNames.Self,
            subject="CN=*.microsoft.com",
            san_dns_names=["sdk.azure-int.net"],
            exportable=True,
            key_type="RSA",
            key_size=2048,
            reuse_key=False,
            content_type=CertificateContentType.PKCS12,
            validity_in_months=24,
        )

        cert_name = "cert-name"

        polling_interval = 0 if self.is_playback() else None
        certificate_client.begin_create_certificate(
            certificate_name=cert_name, policy=cert_policy, _polling_interval=polling_interval
        ).wait()

        certificate_client.begin_delete_certificate(
            certificate_name=cert_name, _polling_interval=polling_interval
        ).wait()
        # [START get_deleted_certificate]

        # get a deleted certificate (requires soft-delete enabled for the vault)
        deleted_certificate = certificate_client.get_deleted_certificate(cert_name)
        print(deleted_certificate.name)

        # if the vault has soft-delete enabled, the certificate's deleted date,
        # scheduled purge date, and recovery id are available
        print(deleted_certificate.deleted_on)
        print(deleted_certificate.scheduled_purge_date)
        print(deleted_certificate.recovery_id)

        # [END get_deleted_certificate]
        # [START recover_deleted_certificate]

        # recover a deleted certificate to its latest version (requires soft-delete enabled for the vault)
        recovered_certificate = certificate_client.begin_recover_deleted_certificate(cert_name).result()

        print(recovered_certificate.id)
        print(recovered_certificate.name)

        # [END recover_deleted_certificate]

    @ResourceGroupPreparer(name_prefix=name_prefix)
    @VaultClientPreparer()
    def test_example_contacts(self, vault_client, **kwargs):
        certificate_client = vault_client.certificates

        # [START create_contacts]
        from azure.keyvault.certificates import CertificateContact
        # Create a list of the contacts that you want to set for this key vault.
        contact_list = [
            CertificateContact(email="admin@contoso.com", name="John Doe", phone="1111111111"),
            CertificateContact(email="admin2@contoso.com", name="John Doe2", phone="2222222222"),
        ]

        contacts = certificate_client.create_contacts(contact_list)
        for contact in contacts:
            print(contact.name)
            print(contact.email)
            print(contact.phone)

        # [END create_contacts]

        # [START get_contacts]

        contacts = certificate_client.get_contacts()

        # Loop through the certificate contacts for this key vault.
        for contact in contacts:
            print(contact.name)
            print(contact.email)
            print(contact.phone)

        # [END get_contacts]

        # [START delete_contacts]

        deleted_contacts = certificate_client.delete_contacts()

        for deleted_contact in deleted_contacts:
            print(deleted_contact.name)
            print(deleted_contact.email)
            print(deleted_contact.phone)

        # [END delete_contacts]

    @ResourceGroupPreparer(name_prefix=name_prefix)
    @VaultClientPreparer()
    def test_example_issuers(self, vault_client, **kwargs):
        certificate_client = vault_client.certificates

        # [START create_issuer]
        from azure.keyvault.certificates import AdministratorContact

        # First we specify the AdministratorContact for a issuer.
        admin_details = [
            AdministratorContact(first_name="John", last_name="Doe", email="admin@microsoft.com", phone="4255555555")
        ]

        issuer = certificate_client.create_issuer(
            issuer_name="issuer1", provider="Test", account_id="keyvaultuser", admin_details=admin_details, enabled=True
        )

        print(issuer.name)
        print(issuer.properties.provider)
        print(issuer.account_id)

        for admin_detail in issuer.admin_details:
            print(admin_detail.first_name)
            print(admin_detail.last_name)
            print(admin_detail.email)
            print(admin_detail.phone)

        # [END create_issuer]

        # [START get_issuer]

        issuer = certificate_client.get_issuer("issuer1")

        print(issuer.name)
        print(issuer.properties.provider)
        print(issuer.account_id)

        for admin_detail in issuer.admin_details:
            print(admin_detail.first_name)
            print(admin_detail.last_name)
            print(admin_detail.email)
            print(admin_detail.phone)

        # [END get_issuer]

        certificate_client.create_issuer(issuer_name="issuer2", provider="Test", account_id="keyvaultuser", enabled=True)

        # [START list_properties_of_issuers]

        issuers = certificate_client.list_properties_of_issuers()

        for issuer in issuers:
            print(issuer.name)
            print(issuer.provider)

        # [END list_properties_of_issuers]

        # [START delete_issuer]

        deleted_issuer = certificate_client.delete_issuer("issuer1")

        print(deleted_issuer.name)
        print(deleted_issuer.properties.provider)
        print(deleted_issuer.account_id)

        for admin_detail in deleted_issuer.admin_details:
            print(admin_detail.first_name)
            print(admin_detail.last_name)
            print(admin_detail.email)
            print(admin_detail.phone)

        # [END delete_issuer]
