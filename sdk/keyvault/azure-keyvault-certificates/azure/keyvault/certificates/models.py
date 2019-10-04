# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
# pylint:disable=too-many-lines

from datetime import datetime

from ._shared import parse_vault_id
from ._shared._generated.v7_0 import models
from .enums import ActionType, KeyUsageType, KeyCurveName, KeyType, SecretContentType

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from typing import Any, Dict, Optional


class AdministratorDetails(object):
    """Details of the organization administrator of the certificate issuer.

    :param str first_name: First name of the issuer.
    :param str last_name: Last name of the issuer.
    :param str email: email of the issuer.
    :param str phone: phone number of the issuer.
    """

    def __init__(self, first_name=None, last_name=None, email=None, phone=None):
        # type: (Optional[str], Optional[str], Optional[str], Optional[str]) -> None
        self._first_name = first_name
        self._last_name = last_name
        self._phone = phone
        self._email = email

    @classmethod
    def _from_admin_details_bundle(cls, admin_details_bundle):
        # type: (models.AdministratorDetails) -> AdministratorDetails
        """Construct a AdministratorDetails from an autorest-generated AdministratorDetailsBundle"""
        return cls(
            email=admin_details_bundle.email_address,
            first_name=admin_details_bundle.first_name,
            last_name=admin_details_bundle.last_name,
            phone=admin_details_bundle.phone,
        )

    @property
    def email(self):
        # type: () -> str
        """:rtype: str"""
        return self._email

    @property
    def first_name(self):
        # type: () -> str
        """:rtype: str"""
        return self._first_name

    @property
    def last_name(self):
        # type: () -> str
        """:rtype: str"""
        return self._last_name

    @property
    def phone(self):
        # type: () -> str
        """:rtype: str"""
        return self._phone


class Error(object):
    """The key vault server error.
    """

    def __init__(self, **kwargs):
        # type: (**Any) -> None
        self._code = kwargs.get("code")
        self._message = kwargs.get("message")
        self._inner_error = kwargs.get("inner_error")

    @property
    def code(self):
        # type: () -> str
        """The error code.

        :rtype: str
        """
        return self._code

    @property
    def message(self):
        # type: () -> str
        """The error message.

        :rtype: str
        """
        return self._message

    @property
    def inner_error(self):
        # type: () -> Error
        """The error itself

        :return models.Error:
        """
        return self._inner_error


class CertificateProperties(object):
    """Certificate properties consists of a certificates metadata.
    """

    def __init__(self, **kwargs):
        # type: (**Any) -> None
        self._attributes = kwargs.get("attributes", None)
        self._id = kwargs.get("cert_id", None)
        self._vault_id = parse_vault_id(self._id)
        self._thumbprint = kwargs.get("thumbprint", None)
        self._tags = kwargs.get("tags", None)

    @classmethod
    def _from_certificate_item(cls, certificate_item):
        # type: (models.CertificateItem) -> CertificateProperties
        """Construct a CertificateProperties from an autorest-generated CertificateItem"""
        return cls(
            attributes=certificate_item.attributes,
            cert_id=certificate_item.id,
            thumbprint=certificate_item.x509_thumbprint,
            tags=certificate_item.tags,
        )

    @property
    def id(self):
        # type: () -> str
        """Certificate identifier.

        :rtype: str
        """
        return self._id

    @property
    def name(self):
        # type: () -> str
        """The name of the certificate.

        :rtype: str
        """
        return self._vault_id.name

    @property
    def enabled(self):
        # type: () -> bool
        """Whether the certificate is enabled or not.

        :rtype: bool
        """
        return self._attributes.enabled if self._attributes else None

    @property
    def not_before(self):
        # type: () -> datetime
        """The datetime before which the certificate is not valid.

        :rtype: datetime
        """
        return self._attributes.not_before if self._attributes else None

    @property
    def expires(self):
        # type: () -> datetime
        """The datetime when the certificate expires.

        :rtype: datetime
        """
        return self._attributes.expires if self._attributes else None

    @property
    def created(self):
        # type: () -> datetime
        """The datetime when the certificate is created.

        :rtype: datetime
        """
        return self._attributes.created if self._attributes else None

    @property
    def updated(self):
        # type: () -> datetime
        """The datetime when the certificate was last updated.

        :rtype: datetime
        """
        return self._attributes.updated if self._attributes else None

    @property
    def recovery_level(self):
        # type: () -> models.DeletionRecoveryLevel
        """The deletion recovery level currently in effect for the certificate.

        :rtype: models.DeletionRecoveryLevel
        """
        return self._attributes.recovery_level if self._attributes else None

    @property
    def vault_url(self):
        # type: () -> str
        """The name of the vault that the certificate is created in.

        :rtype: str
        """
        return self._vault_id.vault_url

    @property
    def thumbprint(self):
        # type: () -> bytes
        """Thumbprint of the certificate.

        :rtype: bytes
        """
        return self._thumbprint

    @property
    def tags(self):
        # type: () -> Dict[str, str]
        """Application specific metadata in the form of key-value pairs.

        :rtype: str
        """
        return self._tags

    @property
    def version(self):
        # type: () -> str
        """The version of the certificate

        :rtype: str
        """
        return self._vault_id.version


class Certificate(object):
    """Consists of a certificate and its attributes

    :param policy: The management policy for the certificate.
    :type policy: ~azure.keyvault.certificates.CertificatePolicy
    :param properties: The certificate's properties.
    :type properties: ~azure.keyvault.certificates.CertificateProperties
    :param bytearray cer: CER contents of the X509 certificate.
    """

    def __init__(
        self,
        policy,  # type: CertificatePolicy
        properties=None,  # type: Optional[CertificateProperties]
        cer=None,  # type: Optional[bytes]
        **kwargs,  # type: **Any
    ):
        # type: (...) -> None
        self._properties = properties
        self._policy = policy
        self._cer = cer
        self._key_id = kwargs.get("key_id", None)
        self._secret_id = kwargs.get("secret_id", None)

    @classmethod
    def _from_certificate_bundle(cls, certificate_bundle):
        # type: (models.CertificateBundle) -> Certificate
        """Construct a certificate from an autorest-generated certificateBundle"""
        # pylint:disable=protected-access
        return cls(
            properties=CertificateProperties._from_certificate_item(certificate_bundle),
            key_id=certificate_bundle.kid,
            secret_id=certificate_bundle.sid,
            policy=CertificatePolicy._from_certificate_policy_bundle(certificate_bundle.policy),
            cer=certificate_bundle.cer,
        )

    @property
    def id(self):
        # type: () -> str
        """Certificate identifier.

        :rtype: str
        """
        return self._properties.id

    @property
    def name(self):
        # type: () -> str
        """The name of the certificate.

        :rtype: str
        """
        return self._properties.name

    @property
    def properties(self):
        # type: () -> CertificateProperties
        """The certificate's properties

        :rtype: ~azure.keyvault.certificates.models.CertificateAttributes
        """
        return self._properties

    @property
    def key_id(self):
        # type: () -> str
        """:rtype: str"""
        return self._key_id

    @property
    def secret_id(self):
        # type: () -> str
        """:rtype: str"""
        return self._secret_id

    @property
    def policy(self):
        # type: () -> CertificatePolicy
        """The management policy of the certificate.

        :rtype: ~azure.keyvault.certificates.CertificatePolicy
        """
        return self._policy

    @property
    def cer(self):
        # type: () -> bytes
        """The CER contents of the certificate.

        :rtype: bytes
        """
        return self._cer


class CertificateOperation(object):
    # pylint:disable=too-many-instance-attributes
    """A certificate operation is returned in case of asynchronous requests.
    """

    def __init__(self, **kwargs):
        # type: (**Any) -> None
        self._id = kwargs.get("cert_operation_id", None)
        self._vault_id = parse_vault_id(self._id)
        self._issuer_name = kwargs.get("issuer_name", None)
        self._certificate_type = kwargs.get("certificate_type", None)
        self._certificate_transparency = kwargs.get("certificate_transparency", None)
        self._csr = kwargs.get("csr", None)
        self._cancellation_requested = kwargs.get("cancellation_requested", None)
        self._status = kwargs.get("status", None)
        self._status_details = kwargs.get("status_details", None)
        self._error = kwargs.get("error", None)
        self._target = kwargs.get("target", None)
        self._request_id = kwargs.get("request_id", None)

    @classmethod
    def _from_certificate_operation_bundle(cls, certificate_operation_bundle):
        # type: (models.CertificateOperation) -> CertificateOperation
        """Construct a CertificateOperation from an autorest-generated CertificateOperation"""
        return cls(
            cert_operation_id=certificate_operation_bundle.id,
            issuer_name=(
                certificate_operation_bundle.issuer_parameters.name
                if certificate_operation_bundle.issuer_parameters
                else None
            ),
            certificate_type=(
                certificate_operation_bundle.issuer_parameters.certificate_type
                if certificate_operation_bundle.issuer_parameters
                else None
            ),
            certificate_transparency=(
                certificate_operation_bundle.issuer_parameters.certificate_transparency
                if certificate_operation_bundle.issuer_parameters
                else None
            ),
            csr=certificate_operation_bundle.csr,
            cancellation_requested=certificate_operation_bundle.cancellation_requested,
            status=certificate_operation_bundle.status,
            status_details=certificate_operation_bundle.status_details,
            error=certificate_operation_bundle.error,
            target=certificate_operation_bundle.target,
            request_id=certificate_operation_bundle.request_id,
        )

    @property
    def id(self):
        # type: () -> str
        """:rtype: str"""
        return self._id

    @property
    def name(self):
        # type: () -> str
        """:rtype: str"""
        return self._vault_id.name

    @property
    def issuer_name(self):
        # type: () -> str
        """The name of the issuer of the certificate.

        :rtype: str
        """
        return self._issuer_name

    @property
    def certificate_type(self):
        # type: () -> str
        """Type of certificate to be requested from the issuer provider.

        :rtype: str
        """
        return self._certificate_type

    @property
    def certificate_transparency(self):
        # type: () -> bool
        """Whether certificates generated under this policy should be published to certificate
        transparency logs.

        :rtype: bool
        """
        return self._certificate_transparency

    @property
    def csr(self):
        # type: () -> bytes
        """The certificate signing request that is being used in this certificate operation.

        :rtype: bytes
        """
        return self._csr

    @property
    def cancellation_requested(self):
        # type: () -> bool
        """Whether cancellation was requested on the certificate operation.

        :rtype: bool
        """
        return self._cancellation_requested

    @property
    def status(self):
        # type: () -> str
        """:rtype: str"""
        return self._status

    @property
    def status_details(self):
        # type: () -> str
        """:rtype: str"""
        return self._status_details

    @property
    def error(self):
        # type: () -> models.Error
        """:rtype: models.Error"""
        return self._error

    @property
    def target(self):
        # type: () -> str
        """Location which contains the result of the certificate operation.

        :rtype: str
        """
        return self._target

    @property
    def request_id(self):
        # type: () -> str
        """Identifier for the certificate operation.

        :rtype: str
        """
        return self._request_id


class CertificatePolicy(object):
    """Management policy for a certificate.

    :param key_properties: Properties of the key backing the certificate.
    :type key_properties: ~azure.keyvault.certificates.models.KeyProperties
    :param content_type: The media type (MIME type) of the secret backing the certificate.
    :type content_type: ~azure.keyvault.certificates.enums.SecretContentType or str
    :param str subject_name: The subject name of the certificate. Should be a valid X509
        distinguished name.
    :param int validity_in_months: The duration that the certificate is valid in months.
    :param lifetime_actions: Actions that will be performed by Key Vault over the lifetime
        of a certificate
    :type lifetime_actions: Iterable[~azure.keyvault.certificates.LifetimeAction]
    :param str issuer_name: Name of the referenced issuer object or reserved names; for example,
        'Self' or 'Unknown"
    :param str certificate_type: Type of certificate to be requested from the issuer provider.
    :param bool certificate_transparency: Indicates if the certificates generated under this policy
        should be published to certificate transparency logs.
    :param san_emails: Subject alternative emails of the X509 object. Only one out of san_emails,
        san_dns_names, and san_upns may be set.
    :type san_emails: Iterable[str]
    :param san_dns_names: Subject alternative DNS names of the X509 object. Only one out of
        san_emails, san_dns_names, and san_upns may be set.
    :type san_dns_names: Iterable[str]
    :param san_upns: Subject alternative user principal names. Only one out of san_emails,
        san_dns_names, and san_upns may be set.
    :type san_upns: Iterable[str]
    """

    # pylint:disable=too-many-instance-attributes
    def __init__(
        self,
        key_properties=None,  # type: Optional[KeyProperties]
        content_type=None,  # type: Optional[models.SecretContentType] or str
        subject_name=None,  # type: Optional[str]
        validity_in_months=None,  # type: Optional[int]
        lifetime_actions=None,  # type: Optional[list[LifetimeAction]]
        issuer_name=None,  # type: Optional[str]
        certificate_type=None,  # type: Optional[str]
        certificate_transparency=None,  # type: Optional[bool]
        **kwargs,  # type: **Any
    ):
        # type: (...) -> None
        self._id = kwargs.get("cert_policy_id", None)
        self._key_properties = key_properties
        self._content_type = content_type
        self._subject_name = subject_name
        self._validity_in_months = validity_in_months
        self._lifetime_actions = lifetime_actions
        self._issuer_name = issuer_name
        self._certificate_type = certificate_type
        self._certificate_transparency = certificate_transparency
        self._attributes = kwargs.get("attributes", None)
        self._san_emails = kwargs.pop("san_emails", None)
        self._san_dns_names = kwargs.pop("san_dns_names", None)
        self._san_upns = kwargs.pop("san_upns", None)

        sans = [self._san_emails, self._san_upns, self._san_dns_names]
        if len([x for x in sans if x is not None]) > 1:
            raise ValueError("You can only set at most one of san_emails, san_dns_names, and san_upns")

    def _to_certificate_policy_bundle(self):
        # type: (CertificatePolicy) -> models.CertificatePolicy

        """Construct a version emulating the generated CertificatePolicy from a wrapped CertificatePolicy"""
        if self.issuer_name or self.certificate_type or self.certificate_transparency:
            issuer_parameters = models.IssuerParameters(
                name=self.issuer_name,
                certificate_type=self.certificate_type,
                certificate_transparency=self.certificate_transparency,
            )
        else:
            issuer_parameters = None

        # pylint:disable=too-many-boolean-expressions
        if (
            self.enabled is not None
            or self.not_before is not None
            or self.expires is not None
            or self.created is not None
            or self.updated is not None
            or self.recovery_level
        ):
            attributes = models.CertificateAttributes(
                enabled=self.enabled,
                not_before=self.not_before,
                expires=self.expires,
                created=self.enabled,
                updated=self.updated,
                recovery_level=self.recovery_level,
            )
        else:
            attributes = None

        if self.lifetime_actions:
            lifetime_actions = []
            for lifetime_action in self.lifetime_actions:
                lifetime_actions.append(
                    models.LifetimeAction(
                        trigger=models.Trigger(
                            lifetime_percentage=lifetime_action.lifetime_percentage,
                            days_before_expiry=lifetime_action.days_before_expiry,
                        ),
                        action=models.Action(
                            action_type=lifetime_action.action_type.value
                            if not isinstance(lifetime_action.action_type, str) and lifetime_action.action_type
                            else lifetime_action.action_type
                        ),
                    )
                )
        else:
            lifetime_actions = None

        # pylint:disable=too-many-boolean-expressions
        if (
            self.subject_name
            or (self.key_properties and self.key_properties.ekus)
            or (self.key_properties and self.key_properties.key_usage)
            or self.san_emails
            or self.san_upns
            or self.san_dns_names
            or self.validity_in_months
        ):
            if self.key_properties and self.key_properties.key_usage:
                key_usage = [k.value if not isinstance(k, str) else k for k in self.key_properties.key_usage]
            else:
                key_usage = None

            sans = [self._san_emails, self._san_upns, self._san_dns_names]
            if len([x for x in sans if x is not None]) > 1:
                raise ValueError("You can only set at most one of san_emails, san_dns_names, and san_upns")

            x509_certificate_properties = models.X509CertificateProperties(
                subject=self.subject_name,
                ekus=self.key_properties.ekus if self.key_properties else None,
                subject_alternative_names=models.SubjectAlternativeNames(
                    emails=self.san_emails, upns=self.san_upns, dns_names=self.san_dns_names
                ),
                key_usage=key_usage,
                validity_in_months=self.validity_in_months,
            )
        else:
            x509_certificate_properties = None

        if self.key_properties and (
            self.key_properties.exportable
            or self.key_properties.key_type
            or self.key_properties.key_size
            or self.key_properties.reuse_key
            or self.key_properties.curve
        ):
            key_properties = models.KeyProperties(
                exportable=self.key_properties.exportable,
                key_type=(
                    self.key_properties.key_type.value
                    if not isinstance(self.key_properties.key_type, str) and self.key_properties.key_type
                    else self.key_properties.key_type
                ),
                key_size=self.key_properties.key_size,
                reuse_key=self.key_properties.reuse_key,
                curve=(
                    self.key_properties.curve.value
                    if not isinstance(self.key_properties.curve, str) and self.key_properties.curve
                    else self.key_properties.curve
                ),
            )
        else:
            key_properties = None

        if self.content_type:
            secret_properties = models.SecretProperties(
                content_type=self.content_type.value
                if not isinstance(self.content_type, str) and self.content_type
                else self.content_type
            )
        else:
            secret_properties = None

        policy_bundle = models.CertificatePolicy(
            id=self.id,
            key_properties=key_properties,
            secret_properties=secret_properties,
            x509_certificate_properties=x509_certificate_properties,
            lifetime_actions=lifetime_actions,
            issuer_parameters=issuer_parameters,
            attributes=attributes,
        )
        return policy_bundle

    @classmethod
    def _from_certificate_policy_bundle(cls, certificate_policy_bundle):
        # type: (models.CertificatePolicy) -> CertificatePolicy
        """Construct a CertificatePolicy from an autorest-generated CertificatePolicy"""
        if certificate_policy_bundle.lifetime_actions:
            lifetime_actions = [
                LifetimeAction(
                    action_type=(ActionType(item.action.action_type) if item.action.action_type else None),
                    lifetime_percentage=item.trigger.lifetime_percentage,
                    days_before_expiry=item.trigger.days_before_expiry,
                )
                for item in certificate_policy_bundle.lifetime_actions
            ]
        else:
            lifetime_actions = None
        key_properties_bundle = certificate_policy_bundle.key_properties
        # pylint:disable=too-many-boolean-expressions
        if key_properties_bundle:
            if (
                certificate_policy_bundle.x509_certificate_properties
                and certificate_policy_bundle.x509_certificate_properties.key_usage
            ):
                key_usage = [KeyUsageType(k) for k in certificate_policy_bundle.x509_certificate_properties.key_usage]
            else:
                key_usage = None

            key_properties = KeyProperties(
                exportable=certificate_policy_bundle.key_properties.exportable,
                key_type=(
                    KeyType(certificate_policy_bundle.key_properties.key_type)
                    if certificate_policy_bundle.key_properties.key_type
                    else None
                ),
                key_size=certificate_policy_bundle.key_properties.key_size,
                reuse_key=certificate_policy_bundle.key_properties.reuse_key,
                curve=(
                    KeyCurveName(certificate_policy_bundle.key_properties.curve)
                    if certificate_policy_bundle.key_properties.curve
                    else None
                ),
                ekus=(
                    certificate_policy_bundle.x509_certificate_properties.ekus
                    if certificate_policy_bundle.x509_certificate_properties
                    else None
                ),
                key_usage=key_usage,
            )
        else:
            key_properties = None
        return cls(
            attributes=certificate_policy_bundle.attributes,
            cert_policy_id=certificate_policy_bundle.id,
            issuer_name=(
                certificate_policy_bundle.issuer_parameters.name
                if certificate_policy_bundle.issuer_parameters
                else None
            ),
            certificate_type=(
                certificate_policy_bundle.issuer_parameters.certificate_type
                if certificate_policy_bundle.issuer_parameters
                else None
            ),
            certificate_transparency=(
                certificate_policy_bundle.issuer_parameters.certificate_transparency
                if certificate_policy_bundle.issuer_parameters
                else None
            ),
            lifetime_actions=lifetime_actions,
            subject_name=(
                certificate_policy_bundle.x509_certificate_properties.subject
                if certificate_policy_bundle.x509_certificate_properties
                else None
            ),
            key_properties=key_properties,
            content_type=(
                SecretContentType(certificate_policy_bundle.secret_properties.content_type)
                if certificate_policy_bundle.secret_properties
                else None
            ),
            san_emails=(
                certificate_policy_bundle.x509_certificate_properties.subject_alternative_names.emails
                if certificate_policy_bundle.x509_certificate_properties
                and certificate_policy_bundle.x509_certificate_properties.subject_alternative_names
                else None
            ),
            san_upns=(
                certificate_policy_bundle.x509_certificate_properties.subject_alternative_names.upns
                if certificate_policy_bundle.x509_certificate_properties
                and certificate_policy_bundle.x509_certificate_properties.subject_alternative_names
                else None
            ),
            san_dns_names=(
                certificate_policy_bundle.x509_certificate_properties.subject_alternative_names.dns_names
                if certificate_policy_bundle.x509_certificate_properties
                and certificate_policy_bundle.x509_certificate_properties.subject_alternative_names
                else None
            ),
            validity_in_months=(
                certificate_policy_bundle.x509_certificate_properties.validity_in_months
                if certificate_policy_bundle.x509_certificate_properties
                else None
            ),
        )

    @property
    def id(self):
        # type: () -> str
        """:rtype: str"""
        return self._id

    @property
    def key_properties(self):
        # type: () -> KeyProperties
        """Properties of the key backing the certificate.

        :rtype: ~azure.keyvault.certificates.models.KeyProperties
        """
        return self._key_properties

    @property
    def content_type(self):
        # type: () -> SecretContentType
        """The media type (MIME type).

        :rtype: ~azure.keyvault.certificates.enums.SecretContentType
        """
        return self._content_type

    @property
    def subject_name(self):
        # type: () -> str
        """:rtype: str"""
        return self._subject_name

    @property
    def san_emails(self):
        # type: () -> list[str]
        """The subject alternative email addresses.

        :rtype: list[str]
        """
        return self._san_emails

    @property
    def san_dns_names(self):
        # type: () -> list[str]
        """The subject alternative domain names.

        :rtype: list[str]
        """
        return self._san_dns_names

    @property
    def san_upns(self):
        # type: () -> list[str]
        """The subject alternative user principal names.

        :rtype: list[str]
        """
        return self._san_upns

    @property
    def validity_in_months(self):
        # type: () -> int
        """The duration that the certificate is valid for in months.

        :rtype: int
        """
        return self._validity_in_months

    @property
    def lifetime_actions(self):
        # type: () -> list[LifetimeAction]
        """Actions and their triggers that will be performed by Key Vault over
        the lifetime of the certificate.

        :rtype: list[~azure.keyvault.certificates.models.LifetimeAction]
        """
        return self._lifetime_actions

    @property
    def issuer_name(self):
        # type: () -> str
        """Name of the referenced issuer object or reserved names for the issuer
        of the certificate.

        :rtype: str
        """
        return self._issuer_name

    @property
    def certificate_type(self):
        # type: () -> str
        """Type of certificate requested from the issuer provider.

        :rtype: str
        """
        return self._certificate_type

    @property
    def certificate_transparency(self):
        # type: () -> bool
        """Whether the certificates generated under this policy should be published
        to certificate transparency logs.

        :rtype: bool
        """
        return self._certificate_transparency

    @property
    def enabled(self):
        # type: () -> bool
        """Whether the certificate is enabled or not.

        :rtype: bool
        """
        return self._attributes.enabled if self._attributes else None

    @property
    def not_before(self):
        # type: () -> datetime
        """The datetime before which the certificate is not valid.

        :rtype: datetime
        """
        return self._attributes.not_before if self._attributes else None

    @property
    def expires(self):
        # type: () -> datetime
        """The datetime when the certificate expires.

        :rtype: datetime
        """
        return self._attributes.expires if self._attributes else None

    @property
    def created(self):
        # type: () -> datetime
        """The datetime when the certificate is created.

        :rtype: datetime
        """
        return self._attributes.created if self._attributes else None

    @property
    def updated(self):
        # type: () -> datetime
        """The datetime when the certificate was last updated.

        :rtype: datetime
        """
        return self._attributes.updated if self._attributes else None

    @property
    def recovery_level(self):
        # type: () -> models.DeletionRecoveryLevel
        """The deletion recovery level currently in effect for the certificate.

        :rtype: DeletionRecoveryLevel
        """
        return self._attributes.recovery_level if self._attributes else None


class Contact(object):
    """The contact information for the vault certificates.

    :param str email: Email address of a contact for the certificate.
    :param str name: Name of a contact for the certificate.
    :param str phone: phone number of a contact for the certificate.
    """

    def __init__(self, email=None, name=None, phone=None):
        # type: (Optional[str], Optional[str], Optional[str]) -> None
        self._email = email
        self._name = name
        self._phone = phone

    def _to_certificate_contacts_item(self):
        # type: (Contact) -> models.Contact
        return models.Contact(email_address=self.email, name=self.name, phone=self.phone)

    @classmethod
    def _from_certificate_contacts_item(cls, contact_item):
        # type: (models.Contact) -> Contact
        """Construct a Contact from an autorest-generated ContactItem."""
        return cls(email=contact_item.email_address, name=contact_item.name, phone=contact_item.phone)

    @property
    def email(self):
        # type: () -> str
        """:rtype: str"""
        return self._email

    @property
    def name(self):
        # type: () -> str
        """:rtype: str"""
        return self._name

    @property
    def phone(self):
        # type: () -> str
        """:rtype: str"""
        return self._phone


class IssuerProperties(object):
    """The properties of an issuer containing the issuer metadata.

    :param str provider: The issuer provider.
    """

    def __init__(self, provider=None, **kwargs):
        # type: (Optional[str], **Any) -> None
        self._id = kwargs.get("issuer_id", None)
        self._vault_id = parse_vault_id(self._id)
        self._provider = provider

    @classmethod
    def _from_issuer_item(cls, issuer_item):
        # type: (models.CertificateIssuerItem) -> IssuerProperties
        """Construct a IssuerProperties from an autorest-generated CertificateIssuerItem"""
        return cls(issuer_id=issuer_item.id, provider=issuer_item.provider)

    @property
    def id(self):
        # type: () -> str
        """:rtype: str"""
        return self._id

    @property
    def name(self):
        # type: () -> str
        # Issuer name is listed under version under vault_id
        """:rtype: str"""
        return self._vault_id.version

    @property
    def provider(self):
        # type: () -> str
        """:rtype: str"""
        return self._provider

    @property
    def vault_url(self):
        # type: () -> str
        """The name of the vault with this issuer.

        :rtype: str
        """
        return self._vault_id.vault_url


class Issuer(object):
    """The issuer for a Key Vault certificate.

    :param properties: The issuer's properties
    :type properties: ~azure.keyvault.certificates.IssuerProperties
    :param str account_id: The username / account name / account id.
    :param str password: The password / secret / account key.
    :param str organization_id: The ID of the organization.
    :param admin_details: Details of the organization administrator.
    :type admin_details: list[~azure.keyvault.certificates.AdministratorDetails]
    """

    def __init__(
        self,
        properties=None,  # type: Optional[IssuerProperties]
        account_id=None,  # type: Optional[str]
        password=None,  # type: Optional[str]
        organization_id=None,  # type: Optional[str]
        admin_details=None,  # type: Optional[List[AdministratorDetails]]
        **kwargs,  # type: **Any
    ):
        # type: (...) -> None
        self._properties = properties
        self._attributes = kwargs.get("attributes", None)
        self._account_id = account_id
        self._password = password
        self._organization_id = organization_id
        self._admin_details = admin_details

    @classmethod
    def _from_issuer_bundle(cls, issuer_bundle):
        # type: (models.IssuerBundle) -> Issuer
        """Construct a Issuer from an autorest-generated IssuerBundle"""
        admin_details = []
        admin_details_service = (
            issuer_bundle.organization_details.admin_details if issuer_bundle.organization_details else None
        )
        if admin_details_service:
            # pylint:disable=protected-access
            for admin_detail in admin_details_service:
                admin_details.append(AdministratorDetails._from_admin_details_bundle(admin_detail))
        return cls(
            properties=IssuerProperties._from_issuer_item(issuer_bundle),  # pylint: disable=protected-access
            attributes=issuer_bundle.attributes,
            account_id=issuer_bundle.credentials.account_id if issuer_bundle.credentials else None,
            password=issuer_bundle.credentials.password if issuer_bundle.credentials else None,
            organization_id=issuer_bundle.organization_details.id if issuer_bundle.organization_details else None,
            admin_details=admin_details,
        )

    @property
    def id(self):
        # type: () -> str
        """:rtype: str"""
        return self._properties.id

    @property
    def name(self):
        # type: () -> str
        # Issuer name is listed under version under vault_id
        """:rtype: str"""
        return self._properties.name

    @property
    def properties(self):
        # type: () -> IssuerProperties
        """The properties of the issuer.

        :rtype: ~azure.keyvault.certificates.models.IssuerProperties
        """
        return self._properties

    @property
    def enabled(self):
        # type: () -> bool
        """Whether the certificate is enabled or not.

        :rtype: bool
        """
        return self._attributes.enabled if self._attributes else None

    @property
    def created(self):
        # type: () -> datetime
        """The datetime when the certificate is created.

        :rtype: datetime
        """
        return self._attributes.created if self._attributes else None

    @property
    def updated(self):
        # type: () -> datetime
        """The datetime when the certificate was last updated.

        :rtype: datetime
        """
        return self._attributes.updated if self._attributes else None

    @property
    def account_id(self):
        # type: () -> str
        """The username/ account name/ account id.

        :rtype: str
        """
        return self._account_id

    @property
    def password(self):
        # type: () -> str
        """The password / secret / account key.

        :rtype: str
        """
        return self._password

    @property
    def organization_id(self):
        # type: () -> str
        """:rtype: str"""
        return self._organization_id

    @property
    def admin_details(self):
        # type: () -> List[AdministratorDetails]
        """Details of the organization administrator of this issuer.

        :rtype: list[~azure.keyvault.certificates.models.AdministratorDetails]
        """
        return self._admin_details


class KeyProperties(object):
    """Properties of the key pair backing a certificate.

    :param bool exportable: Indicates if the private key can be exported.
    :param key_type: The type of key pair to be used for the certificate.
        Possible values include: 'EC', 'EC-HSM', 'RSA', 'RSA-HSM', 'oct'
    :type key_type: str or ~azure.keyvault.certificates.enums.KeyType
    :param int key_size: The key size in bits. For example: 2048, 3072, or 4096
        for RSA.
    :param bool reuse_key: Indicates if the same key pair will be used on certificate
        renewal.
    :param curve: Elliptic curve name. For valid values, see KeyCurveName.
        Possible values include: 'P-256', 'P-384', 'P-521', 'P-256K'
    :type curve: str or ~azure.keyvault.certificates.enums.KeyCurveName
    :param ekus: The enhanced key usages.
    :type ekus: list[str]
    :param key_usage: List of key usages.
    :type key_usage: list[str or ~azure.keyvault.certificates.enums.KeyUsageType]
    """

    def __init__(
        self,
        exportable=None,  # type: Optional[bool]
        key_type=None,  # type: Optional[KeyType]
        key_size=None,  # type: Optional[str]
        reuse_key=None,  # type: Optional[bool]
        curve=None,  # type: Optional[KeyCurveName]
        ekus=None,  # type: Optional[list[str]]
        key_usage=None,  # type: Optional[list[KeyUsageType]]
    ):
        # type: (...) -> None
        self._exportable = exportable
        self._key_type = key_type
        self._key_size = key_size
        self._reuse_key = reuse_key
        self._curve = curve
        self._ekus = ekus
        self._key_usage = key_usage

    @property
    def exportable(self):
        # type: () -> bool
        """Whether the private key can be exported.

        :rtype: bool
        """
        return self._exportable

    @property
    def key_type(self):
        # type: () -> KeyType
        """The type of key pair to be used for the certificate.

        :rtype: ~azure.keyvault.certificates.enums.KeyType
        """
        return self._key_type

    @property
    def key_size(self):
        # type: () -> int
        """The key size in bits.

        :rtype: int
        """
        return self._key_size

    @property
    def reuse_key(self):
        # type: () -> bool
        """Whether the same key pair will be used on certificate renewal.

        :rtype: bool
        """
        return self._reuse_key

    @property
    def curve(self):
        # type: () -> KeyCurveName
        """Elliptic curve name.

        :rtype: ~azure.keyvault.certificates.enums.KeyCurveName
        """
        return self._curve

    @property
    def ekus(self):
        # type: () -> list[str]
        """The enhanced key usage.

        :rtype: list[str]
        """
        return self._ekus

    @property
    def key_usage(self):
        # type: () -> list[KeyUsageType]
        """List of key usages.

        :rtype: list[~azure.keyvault.certificates.enums.KeyUsageType]
        """
        return self._key_usage


class LifetimeAction(object):
    """Action and its trigger that will be performed by certificate Vault over the
    lifetime of a certificate.

    :param action_type: The type of the action. Possible values include: 'EmailContacts',
        'AutoRenew'
    :type action_type: str or ~azure.keyvault.certificates.enums.ActionType
    :param int lifetime_percentage: Percentage of lifetime at which to trigger. Value
        should be between 1 and 99.
    :param int days_before_expiry: Days before expiry to attempt renewal. Value should be between
        1 and validity_in_months multiplied by 27. I.e., if validity_in_months is 36, then value
        should be between 1 and 972 (36 * 27).
    """

    def __init__(self, action_type, lifetime_percentage=None, days_before_expiry=None):
        # type: (ActionType, Optional[int], Optional[int]) -> None
        self._lifetime_percentage = lifetime_percentage
        self._days_before_expiry = days_before_expiry
        self._action_type = action_type

    @property
    def lifetime_percentage(self):
        # type: () -> int
        """Percentage of lifetime at which to trigger.

        :rtype: int
        """
        return self._lifetime_percentage

    @property
    def days_before_expiry(self):
        # type: () -> int
        """Days before expiry to attempt renewal.

        :rtype: int
        """
        return self._days_before_expiry

    @property
    def action_type(self):
        # type: () -> str
        """The type of the action that will be executed.
        Valid values are "EmailContacts" and "AutoRenew"

        :rtype: str or ~azure.keyvault.certificates.enums.ActionType
        """
        return self._action_type


class DeletedCertificate(Certificate):
    """A Deleted Certificate consisting of its previous id, attributes and its
    tags, as well as information on when it will be purged.

    :param properties: The deleted certificate's properties.
    :type properties: ~azure.keyvault.certificates.CertificateProperties
    :param policy: The management policy of the deleted certificate.
    :type policy: ~azure.keyvault.certificates.CertificatePolicy
    :param bytearray cer: CER contents of the X509 certificate.
    """

    def __init__(
        self,
        properties=None,  # type: Optional[CertificateProperties]
        policy=None,  # type: Optional[CertificatePolicy]
        cer=None,  # type: Optional[bytes]
        **kwargs,  # type: **Any
    ):
        # type: (...) -> None
        super(DeletedCertificate, self).__init__(properties=properties, policy=policy, cer=cer, **kwargs)
        self._deleted_date = kwargs.get("deleted_date", None)
        self._recovery_id = kwargs.get("recovery_id", None)
        self._scheduled_purge_date = kwargs.get("scheduled_purge_date", None)

    @classmethod
    def _from_deleted_certificate_item(cls, deleted_certificate_item):
        # type: (models.DeletedCertificateItem) -> DeletedCertificate
        """Construct a DeletedCertificate from an autorest-generated DeletedCertificateItem"""
        return cls(
            properties=CertificateProperties._from_certificate_item(  # pylint: disable=protected-access
                deleted_certificate_item
            ),
            key_id=None,
            secret_id=None,
            policy=None,
            cer=None,
            deleted_date=deleted_certificate_item.deleted_date,
            recovery_id=deleted_certificate_item.recovery_id,
            scheduled_purge_date=deleted_certificate_item.scheduled_purge_date,
        )

    @classmethod
    def _from_deleted_certificate_bundle(cls, deleted_certificate_bundle):
        # type: (models.DeletedCertificateBundle) -> DeletedCertificate
        """Construct a DeletedCertificate from an autorest-generated DeletedCertificateItem"""
        # pylint:disable=protected-access
        return cls(
            properties=CertificateProperties._from_certificate_item(deleted_certificate_bundle),
            key_id=deleted_certificate_bundle.kid,
            secret_id=deleted_certificate_bundle.sid,
            policy=CertificatePolicy._from_certificate_policy_bundle(deleted_certificate_bundle.policy),
            cer=deleted_certificate_bundle.cer,
            deleted_date=deleted_certificate_bundle.deleted_date,
            recovery_id=deleted_certificate_bundle.recovery_id,
            scheduled_purge_date=deleted_certificate_bundle.scheduled_purge_date,
        )

    @property
    def deleted_date(self):
        # type: () -> datetime
        """The datetime that the certificate was deleted.

        :rtype: datetime
        """
        return self._deleted_date

    @property
    def recovery_id(self):
        # type: () -> str
        """The url of the recovery object, used to identify and recover the deleted certificate.

        :rtype: str
        """
        return self._recovery_id

    @property
    def scheduled_purge_date(self):
        # type: () -> datetime
        """The datetime when the certificate is scheduled to be purged.

        :rtype: str
        """
        return self._scheduled_purge_date
