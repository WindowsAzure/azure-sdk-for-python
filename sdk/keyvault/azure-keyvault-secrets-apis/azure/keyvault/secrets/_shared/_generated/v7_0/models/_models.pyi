# Stubs for azure.keyvault.secrets._shared._generated.v7_0.models._models (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from azure.core import HttpResponseError
from msrest.serialization import Model
from typing import Any

class Action(Model):
    action_type: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class AdministratorDetails(Model):
    first_name: Any = ...
    last_name: Any = ...
    email_address: Any = ...
    phone: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class Attributes(Model):
    enabled: Any = ...
    not_before: Any = ...
    expires: Any = ...
    created: Any = ...
    updated: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BackupCertificateResult(Model):
    value: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BackupKeyResult(Model):
    value: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BackupSecretResult(Model):
    value: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BackupStorageResult(Model):
    value: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateAttributes(Attributes):
    recovery_level: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateBundle(Model):
    id: Any = ...
    kid: Any = ...
    sid: Any = ...
    x509_thumbprint: Any = ...
    policy: Any = ...
    cer: Any = ...
    content_type: Any = ...
    attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateCreateParameters(Model):
    certificate_policy: Any = ...
    certificate_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateImportParameters(Model):
    base64_encoded_certificate: Any = ...
    password: Any = ...
    certificate_policy: Any = ...
    certificate_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateIssuerItem(Model):
    id: Any = ...
    provider: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateIssuerListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateIssuerSetParameters(Model):
    provider: Any = ...
    credentials: Any = ...
    organization_details: Any = ...
    attributes: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateIssuerUpdateParameters(Model):
    provider: Any = ...
    credentials: Any = ...
    organization_details: Any = ...
    attributes: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateItem(Model):
    id: Any = ...
    attributes: Any = ...
    tags: Any = ...
    x509_thumbprint: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateMergeParameters(Model):
    x509_certificates: Any = ...
    certificate_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateOperation(Model):
    id: Any = ...
    issuer_parameters: Any = ...
    csr: Any = ...
    cancellation_requested: Any = ...
    status: Any = ...
    status_details: Any = ...
    error: Any = ...
    target: Any = ...
    request_id: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateOperationUpdateParameter(Model):
    cancellation_requested: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificatePolicy(Model):
    id: Any = ...
    key_properties: Any = ...
    secret_properties: Any = ...
    x509_certificate_properties: Any = ...
    lifetime_actions: Any = ...
    issuer_parameters: Any = ...
    attributes: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateRestoreParameters(Model):
    certificate_bundle_backup: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CertificateUpdateParameters(Model):
    certificate_policy: Any = ...
    certificate_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class Contact(Model):
    email_address: Any = ...
    name: Any = ...
    phone: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class Contacts(Model):
    id: Any = ...
    contact_list: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedCertificateBundle(CertificateBundle):
    recovery_id: Any = ...
    scheduled_purge_date: Any = ...
    deleted_date: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedCertificateItem(CertificateItem):
    recovery_id: Any = ...
    scheduled_purge_date: Any = ...
    deleted_date: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedCertificateListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyBundle(Model):
    key: Any = ...
    attributes: Any = ...
    tags: Any = ...
    managed: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedKeyBundle(KeyBundle):
    recovery_id: Any = ...
    scheduled_purge_date: Any = ...
    deleted_date: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyItem(Model):
    kid: Any = ...
    attributes: Any = ...
    tags: Any = ...
    managed: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedKeyItem(KeyItem):
    recovery_id: Any = ...
    scheduled_purge_date: Any = ...
    deleted_date: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedKeyListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SasDefinitionBundle(Model):
    id: Any = ...
    secret_id: Any = ...
    template_uri: Any = ...
    sas_type: Any = ...
    validity_period: Any = ...
    attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedSasDefinitionBundle(SasDefinitionBundle):
    recovery_id: Any = ...
    scheduled_purge_date: Any = ...
    deleted_date: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SasDefinitionItem(Model):
    id: Any = ...
    secret_id: Any = ...
    attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedSasDefinitionItem(SasDefinitionItem):
    recovery_id: Any = ...
    scheduled_purge_date: Any = ...
    deleted_date: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedSasDefinitionListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SecretBundle(Model):
    value: Any = ...
    id: Any = ...
    content_type: Any = ...
    attributes: Any = ...
    tags: Any = ...
    kid: Any = ...
    managed: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedSecretBundle(SecretBundle):
    recovery_id: Any = ...
    scheduled_purge_date: Any = ...
    deleted_date: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SecretItem(Model):
    id: Any = ...
    attributes: Any = ...
    tags: Any = ...
    content_type: Any = ...
    managed: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedSecretItem(SecretItem):
    recovery_id: Any = ...
    scheduled_purge_date: Any = ...
    deleted_date: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedSecretListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageAccountItem(Model):
    id: Any = ...
    resource_id: Any = ...
    attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedStorageAccountItem(StorageAccountItem):
    recovery_id: Any = ...
    scheduled_purge_date: Any = ...
    deleted_date: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageBundle(Model):
    id: Any = ...
    resource_id: Any = ...
    active_key_name: Any = ...
    auto_regenerate_key: Any = ...
    regeneration_period: Any = ...
    attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedStorageBundle(StorageBundle):
    recovery_id: Any = ...
    scheduled_purge_date: Any = ...
    deleted_date: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DeletedStorageListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class Error(Model):
    code: Any = ...
    message: Any = ...
    inner_error: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class IssuerAttributes(Model):
    enabled: Any = ...
    created: Any = ...
    updated: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class IssuerBundle(Model):
    id: Any = ...
    provider: Any = ...
    credentials: Any = ...
    organization_details: Any = ...
    attributes: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class IssuerCredentials(Model):
    account_id: Any = ...
    password: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class IssuerParameters(Model):
    name: Any = ...
    certificate_type: Any = ...
    certificate_transparency: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class JsonWebKey(Model):
    kid: Any = ...
    kty: Any = ...
    key_ops: Any = ...
    n: Any = ...
    e: Any = ...
    d: Any = ...
    dp: Any = ...
    dq: Any = ...
    qi: Any = ...
    p: Any = ...
    q: Any = ...
    k: Any = ...
    t: Any = ...
    crv: Any = ...
    x: Any = ...
    y: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyAttributes(Attributes):
    recovery_level: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyCreateParameters(Model):
    kty: Any = ...
    key_size: Any = ...
    key_ops: Any = ...
    key_attributes: Any = ...
    tags: Any = ...
    curve: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyImportParameters(Model):
    hsm: Any = ...
    key: Any = ...
    key_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyOperationResult(Model):
    kid: Any = ...
    result: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyOperationsParameters(Model):
    algorithm: Any = ...
    value: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyProperties(Model):
    exportable: Any = ...
    key_type: Any = ...
    key_size: Any = ...
    reuse_key: Any = ...
    curve: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyRestoreParameters(Model):
    key_bundle_backup: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeySignParameters(Model):
    algorithm: Any = ...
    value: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyUpdateParameters(Model):
    key_ops: Any = ...
    key_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyVaultError(Model):
    error: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyVaultErrorException(HttpResponseError):
    error: Any = ...
    def __init__(self, response: Any, deserialize: Any, *args: Any) -> None: ...

class KeyVerifyParameters(Model):
    algorithm: Any = ...
    digest: Any = ...
    signature: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyVerifyResult(Model):
    value: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class LifetimeAction(Model):
    trigger: Any = ...
    action: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class OrganizationDetails(Model):
    id: Any = ...
    admin_details: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class PendingCertificateSigningRequestResult(Model):
    value: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SasDefinitionAttributes(Model):
    enabled: Any = ...
    created: Any = ...
    updated: Any = ...
    recovery_level: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SasDefinitionCreateParameters(Model):
    template_uri: Any = ...
    sas_type: Any = ...
    validity_period: Any = ...
    sas_definition_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SasDefinitionListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SasDefinitionUpdateParameters(Model):
    template_uri: Any = ...
    sas_type: Any = ...
    validity_period: Any = ...
    sas_definition_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SecretAttributes(Attributes):
    recovery_level: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SecretListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SecretProperties(Model):
    content_type: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SecretRestoreParameters(Model):
    secret_bundle_backup: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SecretSetParameters(Model):
    value: Any = ...
    tags: Any = ...
    content_type: Any = ...
    secret_attributes: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SecretUpdateParameters(Model):
    content_type: Any = ...
    secret_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageAccountAttributes(Model):
    enabled: Any = ...
    created: Any = ...
    updated: Any = ...
    recovery_level: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageAccountCreateParameters(Model):
    resource_id: Any = ...
    active_key_name: Any = ...
    auto_regenerate_key: Any = ...
    regeneration_period: Any = ...
    storage_account_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageAccountRegenerteKeyParameters(Model):
    key_name: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageAccountUpdateParameters(Model):
    active_key_name: Any = ...
    auto_regenerate_key: Any = ...
    regeneration_period: Any = ...
    storage_account_attributes: Any = ...
    tags: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageListResult(Model):
    value: Any = ...
    next_link: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageRestoreParameters(Model):
    storage_bundle_backup: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SubjectAlternativeNames(Model):
    emails: Any = ...
    dns_names: Any = ...
    upns: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class Trigger(Model):
    lifetime_percentage: Any = ...
    days_before_expiry: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class X509CertificateProperties(Model):
    subject: Any = ...
    ekus: Any = ...
    subject_alternative_names: Any = ...
    key_usage: Any = ...
    validity_in_months: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...
