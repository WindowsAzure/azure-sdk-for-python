# Stubs for azure.keyvault.certificates._shared._generated.v2016_10_01.operations._key_vault_client_operations (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any, Optional

class KeyVaultClientOperationsMixin:
    def create_key(self, vault_base_url: Any, key_name: Any, kty: Any, key_size: Optional[Any] = ..., key_ops: Optional[Any] = ..., key_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., curve: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def import_key(self, vault_base_url: Any, key_name: Any, key: Any, hsm: Optional[Any] = ..., key_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def delete_key(self, vault_base_url: Any, key_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def update_key(self, vault_base_url: Any, key_name: Any, key_version: Any, key_ops: Optional[Any] = ..., key_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_key(self, vault_base_url: Any, key_name: Any, key_version: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_key_versions(self, vault_base_url: Any, key_name: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_keys(self, vault_base_url: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def backup_key(self, vault_base_url: Any, key_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def restore_key(self, vault_base_url: Any, key_bundle_backup: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def encrypt(self, vault_base_url: Any, key_name: Any, key_version: Any, algorithm: Any, value: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def decrypt(self, vault_base_url: Any, key_name: Any, key_version: Any, algorithm: Any, value: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def sign(self, vault_base_url: Any, key_name: Any, key_version: Any, algorithm: Any, value: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def verify(self, vault_base_url: Any, key_name: Any, key_version: Any, algorithm: Any, digest: Any, signature: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def wrap_key(self, vault_base_url: Any, key_name: Any, key_version: Any, algorithm: Any, value: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def unwrap_key(self, vault_base_url: Any, key_name: Any, key_version: Any, algorithm: Any, value: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_deleted_keys(self, vault_base_url: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_deleted_key(self, vault_base_url: Any, key_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def purge_deleted_key(self, vault_base_url: Any, key_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def recover_deleted_key(self, vault_base_url: Any, key_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def set_secret(self, vault_base_url: Any, secret_name: Any, value: Any, tags: Optional[Any] = ..., content_type: Optional[Any] = ..., secret_attributes: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def delete_secret(self, vault_base_url: Any, secret_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def update_secret(self, vault_base_url: Any, secret_name: Any, secret_version: Any, content_type: Optional[Any] = ..., secret_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_secret(self, vault_base_url: Any, secret_name: Any, secret_version: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_secrets(self, vault_base_url: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_secret_versions(self, vault_base_url: Any, secret_name: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_deleted_secrets(self, vault_base_url: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_deleted_secret(self, vault_base_url: Any, secret_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def purge_deleted_secret(self, vault_base_url: Any, secret_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def recover_deleted_secret(self, vault_base_url: Any, secret_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def backup_secret(self, vault_base_url: Any, secret_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def restore_secret(self, vault_base_url: Any, secret_bundle_backup: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_certificates(self, vault_base_url: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def delete_certificate(self, vault_base_url: Any, certificate_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def set_certificate_contacts(self, vault_base_url: Any, contact_list: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_certificate_contacts(self, vault_base_url: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def delete_certificate_contacts(self, vault_base_url: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_certificate_issuers(self, vault_base_url: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def set_certificate_issuer(self, vault_base_url: Any, issuer_name: Any, provider: Any, credentials: Optional[Any] = ..., organization_details: Optional[Any] = ..., attributes: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def update_certificate_issuer(self, vault_base_url: Any, issuer_name: Any, provider: Optional[Any] = ..., credentials: Optional[Any] = ..., organization_details: Optional[Any] = ..., attributes: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_certificate_issuer(self, vault_base_url: Any, issuer_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def delete_certificate_issuer(self, vault_base_url: Any, issuer_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def create_certificate(self, vault_base_url: Any, certificate_name: Any, certificate_policy: Optional[Any] = ..., certificate_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def import_certificate(self, vault_base_url: Any, certificate_name: Any, base64_encoded_certificate: Any, password: Optional[Any] = ..., certificate_policy: Optional[Any] = ..., certificate_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_certificate_versions(self, vault_base_url: Any, certificate_name: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_certificate_policy(self, vault_base_url: Any, certificate_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def update_certificate_policy(self, vault_base_url: Any, certificate_name: Any, certificate_policy: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def update_certificate(self, vault_base_url: Any, certificate_name: Any, certificate_version: Any, certificate_policy: Optional[Any] = ..., certificate_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_certificate(self, vault_base_url: Any, certificate_name: Any, certificate_version: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def update_certificate_operation(self, vault_base_url: Any, certificate_name: Any, cancellation_requested: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_certificate_operation(self, vault_base_url: Any, certificate_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def delete_certificate_operation(self, vault_base_url: Any, certificate_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def merge_certificate(self, vault_base_url: Any, certificate_name: Any, x509_certificates: Any, certificate_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_deleted_certificates(self, vault_base_url: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_deleted_certificate(self, vault_base_url: Any, certificate_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def purge_deleted_certificate(self, vault_base_url: Any, certificate_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def recover_deleted_certificate(self, vault_base_url: Any, certificate_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_storage_accounts(self, vault_base_url: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def delete_storage_account(self, vault_base_url: Any, storage_account_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_storage_account(self, vault_base_url: Any, storage_account_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def set_storage_account(self, vault_base_url: Any, storage_account_name: Any, resource_id: Any, active_key_name: Any, auto_regenerate_key: Any, regeneration_period: Optional[Any] = ..., storage_account_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def update_storage_account(self, vault_base_url: Any, storage_account_name: Any, active_key_name: Optional[Any] = ..., auto_regenerate_key: Optional[Any] = ..., regeneration_period: Optional[Any] = ..., storage_account_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def regenerate_storage_account_key(self, vault_base_url: Any, storage_account_name: Any, key_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_sas_definitions(self, vault_base_url: Any, storage_account_name: Any, maxresults: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def delete_sas_definition(self, vault_base_url: Any, storage_account_name: Any, sas_definition_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def get_sas_definition(self, vault_base_url: Any, storage_account_name: Any, sas_definition_name: Any, cls: Optional[Any] = ..., **kwargs: Any): ...
    def set_sas_definition(self, vault_base_url: Any, storage_account_name: Any, sas_definition_name: Any, parameters: Any, sas_definition_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
    def update_sas_definition(self, vault_base_url: Any, storage_account_name: Any, sas_definition_name: Any, parameters: Optional[Any] = ..., sas_definition_attributes: Optional[Any] = ..., tags: Optional[Any] = ..., cls: Optional[Any] = ..., **kwargs: Any): ...
