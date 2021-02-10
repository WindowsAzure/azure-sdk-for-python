# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import datetime
from typing import Dict, List, Optional, Union

from azure.core.exceptions import HttpResponseError
import msrest.serialization

from ._key_vault_client_enums import *


class Attributes(msrest.serialization.Model):
    """The object attributes managed by the KeyVault service.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param enabled: Determines whether the object is enabled.
    :type enabled: bool
    :param not_before: Not before date in UTC.
    :type not_before: ~datetime.datetime
    :param expires: Expiry date in UTC.
    :type expires: ~datetime.datetime
    :ivar created: Creation time in UTC.
    :vartype created: ~datetime.datetime
    :ivar updated: Last updated time in UTC.
    :vartype updated: ~datetime.datetime
    """

    _validation = {
        'created': {'readonly': True},
        'updated': {'readonly': True},
    }

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'not_before': {'key': 'nbf', 'type': 'unix-time'},
        'expires': {'key': 'exp', 'type': 'unix-time'},
        'created': {'key': 'created', 'type': 'unix-time'},
        'updated': {'key': 'updated', 'type': 'unix-time'},
    }

    def __init__(
        self,
        *,
        enabled: Optional[bool] = None,
        not_before: Optional[datetime.datetime] = None,
        expires: Optional[datetime.datetime] = None,
        **kwargs
    ):
        super(Attributes, self).__init__(**kwargs)
        self.enabled = enabled
        self.not_before = not_before
        self.expires = expires
        self.created = None
        self.updated = None


class BackupKeyResult(msrest.serialization.Model):
    """The backup key result, containing the backup blob.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: The backup blob containing the backed up key.
    :vartype value: bytes
    """

    _validation = {
        'value': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': 'base64'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(BackupKeyResult, self).__init__(**kwargs)
        self.value = None


class KeyBundle(msrest.serialization.Model):
    """A KeyBundle consisting of a WebKey plus its attributes.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param key: The Json web key.
    :type key: ~azure.keyvault.v7_2.models.JsonWebKey
    :param attributes: The key management attributes.
    :type attributes: ~azure.keyvault.v7_2.models.KeyAttributes
    :param tags: A set of tags. Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    :ivar managed: True if the key's lifetime is managed by key vault. If this is a key backing a
     certificate, then managed will be true.
    :vartype managed: bool
    """

    _validation = {
        'managed': {'readonly': True},
    }

    _attribute_map = {
        'key': {'key': 'key', 'type': 'JsonWebKey'},
        'attributes': {'key': 'attributes', 'type': 'KeyAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'managed': {'key': 'managed', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        key: Optional["JsonWebKey"] = None,
        attributes: Optional["KeyAttributes"] = None,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(KeyBundle, self).__init__(**kwargs)
        self.key = key
        self.attributes = attributes
        self.tags = tags
        self.managed = None


class DeletedKeyBundle(KeyBundle):
    """A DeletedKeyBundle consisting of a WebKey plus its Attributes and deletion info.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param key: The Json web key.
    :type key: ~azure.keyvault.v7_2.models.JsonWebKey
    :param attributes: The key management attributes.
    :type attributes: ~azure.keyvault.v7_2.models.KeyAttributes
    :param tags: A set of tags. Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    :ivar managed: True if the key's lifetime is managed by key vault. If this is a key backing a
     certificate, then managed will be true.
    :vartype managed: bool
    :param recovery_id: The url of the recovery object, used to identify and recover the deleted
     key.
    :type recovery_id: str
    :ivar scheduled_purge_date: The time when the key is scheduled to be purged, in UTC.
    :vartype scheduled_purge_date: ~datetime.datetime
    :ivar deleted_date: The time when the key was deleted, in UTC.
    :vartype deleted_date: ~datetime.datetime
    """

    _validation = {
        'managed': {'readonly': True},
        'scheduled_purge_date': {'readonly': True},
        'deleted_date': {'readonly': True},
    }

    _attribute_map = {
        'key': {'key': 'key', 'type': 'JsonWebKey'},
        'attributes': {'key': 'attributes', 'type': 'KeyAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'managed': {'key': 'managed', 'type': 'bool'},
        'recovery_id': {'key': 'recoveryId', 'type': 'str'},
        'scheduled_purge_date': {'key': 'scheduledPurgeDate', 'type': 'unix-time'},
        'deleted_date': {'key': 'deletedDate', 'type': 'unix-time'},
    }

    def __init__(
        self,
        *,
        key: Optional["JsonWebKey"] = None,
        attributes: Optional["KeyAttributes"] = None,
        tags: Optional[Dict[str, str]] = None,
        recovery_id: Optional[str] = None,
        **kwargs
    ):
        super(DeletedKeyBundle, self).__init__(key=key, attributes=attributes, tags=tags, **kwargs)
        self.recovery_id = recovery_id
        self.scheduled_purge_date = None
        self.deleted_date = None


class KeyItem(msrest.serialization.Model):
    """The key item containing key metadata.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param kid: Key identifier.
    :type kid: str
    :param attributes: The key management attributes.
    :type attributes: ~azure.keyvault.v7_2.models.KeyAttributes
    :param tags: A set of tags. Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    :ivar managed: True if the key's lifetime is managed by key vault. If this is a key backing a
     certificate, then managed will be true.
    :vartype managed: bool
    """

    _validation = {
        'managed': {'readonly': True},
    }

    _attribute_map = {
        'kid': {'key': 'kid', 'type': 'str'},
        'attributes': {'key': 'attributes', 'type': 'KeyAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'managed': {'key': 'managed', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        kid: Optional[str] = None,
        attributes: Optional["KeyAttributes"] = None,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(KeyItem, self).__init__(**kwargs)
        self.kid = kid
        self.attributes = attributes
        self.tags = tags
        self.managed = None


class DeletedKeyItem(KeyItem):
    """The deleted key item containing the deleted key metadata and information about deletion.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param kid: Key identifier.
    :type kid: str
    :param attributes: The key management attributes.
    :type attributes: ~azure.keyvault.v7_2.models.KeyAttributes
    :param tags: A set of tags. Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    :ivar managed: True if the key's lifetime is managed by key vault. If this is a key backing a
     certificate, then managed will be true.
    :vartype managed: bool
    :param recovery_id: The url of the recovery object, used to identify and recover the deleted
     key.
    :type recovery_id: str
    :ivar scheduled_purge_date: The time when the key is scheduled to be purged, in UTC.
    :vartype scheduled_purge_date: ~datetime.datetime
    :ivar deleted_date: The time when the key was deleted, in UTC.
    :vartype deleted_date: ~datetime.datetime
    """

    _validation = {
        'managed': {'readonly': True},
        'scheduled_purge_date': {'readonly': True},
        'deleted_date': {'readonly': True},
    }

    _attribute_map = {
        'kid': {'key': 'kid', 'type': 'str'},
        'attributes': {'key': 'attributes', 'type': 'KeyAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'managed': {'key': 'managed', 'type': 'bool'},
        'recovery_id': {'key': 'recoveryId', 'type': 'str'},
        'scheduled_purge_date': {'key': 'scheduledPurgeDate', 'type': 'unix-time'},
        'deleted_date': {'key': 'deletedDate', 'type': 'unix-time'},
    }

    def __init__(
        self,
        *,
        kid: Optional[str] = None,
        attributes: Optional["KeyAttributes"] = None,
        tags: Optional[Dict[str, str]] = None,
        recovery_id: Optional[str] = None,
        **kwargs
    ):
        super(DeletedKeyItem, self).__init__(kid=kid, attributes=attributes, tags=tags, **kwargs)
        self.recovery_id = recovery_id
        self.scheduled_purge_date = None
        self.deleted_date = None


class DeletedKeyListResult(msrest.serialization.Model):
    """A list of keys that have been deleted in this vault.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: A response message containing a list of deleted keys in the vault along with a
     link to the next page of deleted keys.
    :vartype value: list[~azure.keyvault.v7_2.models.DeletedKeyItem]
    :ivar next_link: The URL to get the next set of deleted keys.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[DeletedKeyItem]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DeletedKeyListResult, self).__init__(**kwargs)
        self.value = None
        self.next_link = None


class Error(msrest.serialization.Model):
    """The key vault server error.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar code: The error code.
    :vartype code: str
    :ivar message: The error message.
    :vartype message: str
    :ivar inner_error: The key vault server error.
    :vartype inner_error: ~azure.keyvault.v7_2.models.Error
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'inner_error': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'inner_error': {'key': 'innererror', 'type': 'Error'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Error, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.inner_error = None


class JsonWebKey(msrest.serialization.Model):
    """As of http://tools.ietf.org/html/draft-ietf-jose-json-web-key-18.

    :param kid: Key identifier.
    :type kid: str
    :param kty: JsonWebKey Key Type (kty), as defined in https://tools.ietf.org/html/draft-ietf-
     jose-json-web-algorithms-40. Possible values include: "EC", "EC-HSM", "RSA", "RSA-HSM", "oct",
     "oct-HSM".
    :type kty: str or ~azure.keyvault.v7_2.models.JsonWebKeyType
    :param key_ops:
    :type key_ops: list[str]
    :param n: RSA modulus.
    :type n: bytes
    :param e: RSA public exponent.
    :type e: bytes
    :param d: RSA private exponent, or the D component of an EC private key.
    :type d: bytes
    :param dp: RSA private key parameter.
    :type dp: bytes
    :param dq: RSA private key parameter.
    :type dq: bytes
    :param qi: RSA private key parameter.
    :type qi: bytes
    :param p: RSA secret prime.
    :type p: bytes
    :param q: RSA secret prime, with p < q.
    :type q: bytes
    :param k: Symmetric key.
    :type k: bytes
    :param t: Protected Key, used with 'Bring Your Own Key'.
    :type t: bytes
    :param crv: Elliptic curve name. For valid values, see JsonWebKeyCurveName. Possible values
     include: "P-256", "P-384", "P-521", "P-256K".
    :type crv: str or ~azure.keyvault.v7_2.models.JsonWebKeyCurveName
    :param x: X component of an EC public key.
    :type x: bytes
    :param y: Y component of an EC public key.
    :type y: bytes
    """

    _attribute_map = {
        'kid': {'key': 'kid', 'type': 'str'},
        'kty': {'key': 'kty', 'type': 'str'},
        'key_ops': {'key': 'key_ops', 'type': '[str]'},
        'n': {'key': 'n', 'type': 'base64'},
        'e': {'key': 'e', 'type': 'base64'},
        'd': {'key': 'd', 'type': 'base64'},
        'dp': {'key': 'dp', 'type': 'base64'},
        'dq': {'key': 'dq', 'type': 'base64'},
        'qi': {'key': 'qi', 'type': 'base64'},
        'p': {'key': 'p', 'type': 'base64'},
        'q': {'key': 'q', 'type': 'base64'},
        'k': {'key': 'k', 'type': 'base64'},
        't': {'key': 'key_hsm', 'type': 'base64'},
        'crv': {'key': 'crv', 'type': 'str'},
        'x': {'key': 'x', 'type': 'base64'},
        'y': {'key': 'y', 'type': 'base64'},
    }

    def __init__(
        self,
        *,
        kid: Optional[str] = None,
        kty: Optional[Union[str, "JsonWebKeyType"]] = None,
        key_ops: Optional[List[str]] = None,
        n: Optional[bytes] = None,
        e: Optional[bytes] = None,
        d: Optional[bytes] = None,
        dp: Optional[bytes] = None,
        dq: Optional[bytes] = None,
        qi: Optional[bytes] = None,
        p: Optional[bytes] = None,
        q: Optional[bytes] = None,
        k: Optional[bytes] = None,
        t: Optional[bytes] = None,
        crv: Optional[Union[str, "JsonWebKeyCurveName"]] = None,
        x: Optional[bytes] = None,
        y: Optional[bytes] = None,
        **kwargs
    ):
        super(JsonWebKey, self).__init__(**kwargs)
        self.kid = kid
        self.kty = kty
        self.key_ops = key_ops
        self.n = n
        self.e = e
        self.d = d
        self.dp = dp
        self.dq = dq
        self.qi = qi
        self.p = p
        self.q = q
        self.k = k
        self.t = t
        self.crv = crv
        self.x = x
        self.y = y


class KeyAttributes(Attributes):
    """The attributes of a key managed by the key vault service.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param enabled: Determines whether the object is enabled.
    :type enabled: bool
    :param not_before: Not before date in UTC.
    :type not_before: ~datetime.datetime
    :param expires: Expiry date in UTC.
    :type expires: ~datetime.datetime
    :ivar created: Creation time in UTC.
    :vartype created: ~datetime.datetime
    :ivar updated: Last updated time in UTC.
    :vartype updated: ~datetime.datetime
    :ivar recoverable_days: softDelete data retention days. Value should be >=7 and <=90 when
     softDelete enabled, otherwise 0.
    :vartype recoverable_days: int
    :ivar recovery_level: Reflects the deletion recovery level currently in effect for keys in the
     current vault. If it contains 'Purgeable' the key can be permanently deleted by a privileged
     user; otherwise, only the system can purge the key, at the end of the retention interval.
     Possible values include: "Purgeable", "Recoverable+Purgeable", "Recoverable",
     "Recoverable+ProtectedSubscription", "CustomizedRecoverable+Purgeable",
     "CustomizedRecoverable", "CustomizedRecoverable+ProtectedSubscription".
    :vartype recovery_level: str or ~azure.keyvault.v7_2.models.DeletionRecoveryLevel
    """

    _validation = {
        'created': {'readonly': True},
        'updated': {'readonly': True},
        'recoverable_days': {'readonly': True},
        'recovery_level': {'readonly': True},
    }

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'not_before': {'key': 'nbf', 'type': 'unix-time'},
        'expires': {'key': 'exp', 'type': 'unix-time'},
        'created': {'key': 'created', 'type': 'unix-time'},
        'updated': {'key': 'updated', 'type': 'unix-time'},
        'recoverable_days': {'key': 'recoverableDays', 'type': 'int'},
        'recovery_level': {'key': 'recoveryLevel', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        enabled: Optional[bool] = None,
        not_before: Optional[datetime.datetime] = None,
        expires: Optional[datetime.datetime] = None,
        **kwargs
    ):
        super(KeyAttributes, self).__init__(enabled=enabled, not_before=not_before, expires=expires, **kwargs)
        self.recoverable_days = None
        self.recovery_level = None


class KeyCreateParameters(msrest.serialization.Model):
    """The key create parameters.

    All required parameters must be populated in order to send to Azure.

    :param kty: Required. The type of key to create. For valid values, see JsonWebKeyType. Possible
     values include: "EC", "EC-HSM", "RSA", "RSA-HSM", "oct", "oct-HSM".
    :type kty: str or ~azure.keyvault.v7_2.models.JsonWebKeyType
    :param key_size: The key size in bits. For example: 2048, 3072, or 4096 for RSA.
    :type key_size: int
    :param public_exponent: The public exponent for a RSA key.
    :type public_exponent: int
    :param key_ops:
    :type key_ops: list[str or ~azure.keyvault.v7_2.models.JsonWebKeyOperation]
    :param key_attributes: The attributes of a key managed by the key vault service.
    :type key_attributes: ~azure.keyvault.v7_2.models.KeyAttributes
    :param tags: A set of tags. Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    :param curve: Elliptic curve name. For valid values, see JsonWebKeyCurveName. Possible values
     include: "P-256", "P-384", "P-521", "P-256K".
    :type curve: str or ~azure.keyvault.v7_2.models.JsonWebKeyCurveName
    """

    _validation = {
        'kty': {'required': True},
    }

    _attribute_map = {
        'kty': {'key': 'kty', 'type': 'str'},
        'key_size': {'key': 'key_size', 'type': 'int'},
        'public_exponent': {'key': 'public_exponent', 'type': 'int'},
        'key_ops': {'key': 'key_ops', 'type': '[str]'},
        'key_attributes': {'key': 'attributes', 'type': 'KeyAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'curve': {'key': 'crv', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        kty: Union[str, "JsonWebKeyType"],
        key_size: Optional[int] = None,
        public_exponent: Optional[int] = None,
        key_ops: Optional[List[Union[str, "JsonWebKeyOperation"]]] = None,
        key_attributes: Optional["KeyAttributes"] = None,
        tags: Optional[Dict[str, str]] = None,
        curve: Optional[Union[str, "JsonWebKeyCurveName"]] = None,
        **kwargs
    ):
        super(KeyCreateParameters, self).__init__(**kwargs)
        self.kty = kty
        self.key_size = key_size
        self.public_exponent = public_exponent
        self.key_ops = key_ops
        self.key_attributes = key_attributes
        self.tags = tags
        self.curve = curve


class KeyImportParameters(msrest.serialization.Model):
    """The key import parameters.

    All required parameters must be populated in order to send to Azure.

    :param hsm: Whether to import as a hardware key (HSM) or software key.
    :type hsm: bool
    :param key: Required. The Json web key.
    :type key: ~azure.keyvault.v7_2.models.JsonWebKey
    :param key_attributes: The key management attributes.
    :type key_attributes: ~azure.keyvault.v7_2.models.KeyAttributes
    :param tags: A set of tags. Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    """

    _validation = {
        'key': {'required': True},
    }

    _attribute_map = {
        'hsm': {'key': 'Hsm', 'type': 'bool'},
        'key': {'key': 'key', 'type': 'JsonWebKey'},
        'key_attributes': {'key': 'attributes', 'type': 'KeyAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        *,
        key: "JsonWebKey",
        hsm: Optional[bool] = None,
        key_attributes: Optional["KeyAttributes"] = None,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(KeyImportParameters, self).__init__(**kwargs)
        self.hsm = hsm
        self.key = key
        self.key_attributes = key_attributes
        self.tags = tags


class KeyListResult(msrest.serialization.Model):
    """The key list result.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: A response message containing a list of keys in the key vault along with a link to
     the next page of keys.
    :vartype value: list[~azure.keyvault.v7_2.models.KeyItem]
    :ivar next_link: The URL to get the next set of keys.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[KeyItem]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(KeyListResult, self).__init__(**kwargs)
        self.value = None
        self.next_link = None


class KeyOperationResult(msrest.serialization.Model):
    """The key operation result.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar kid: Key identifier.
    :vartype kid: str
    :ivar result:
    :vartype result: bytes
    :ivar iv:
    :vartype iv: bytes
    :ivar authentication_tag:
    :vartype authentication_tag: bytes
    :ivar additional_authenticated_data:
    :vartype additional_authenticated_data: bytes
    """

    _validation = {
        'kid': {'readonly': True},
        'result': {'readonly': True},
        'iv': {'readonly': True},
        'authentication_tag': {'readonly': True},
        'additional_authenticated_data': {'readonly': True},
    }

    _attribute_map = {
        'kid': {'key': 'kid', 'type': 'str'},
        'result': {'key': 'value', 'type': 'base64'},
        'iv': {'key': 'iv', 'type': 'base64'},
        'authentication_tag': {'key': 'tag', 'type': 'base64'},
        'additional_authenticated_data': {'key': 'aad', 'type': 'base64'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(KeyOperationResult, self).__init__(**kwargs)
        self.kid = None
        self.result = None
        self.iv = None
        self.authentication_tag = None
        self.additional_authenticated_data = None


class KeyOperationsParameters(msrest.serialization.Model):
    """The key operations parameters.

    All required parameters must be populated in order to send to Azure.

    :param algorithm: Required. algorithm identifier. Possible values include: "RSA-OAEP", "RSA-
     OAEP-256", "RSA1_5", "A128GCM", "A192GCM", "A256GCM", "A128KW", "A192KW", "A256KW", "A128CBC",
     "A192CBC", "A256CBC", "A128CBCPAD", "A192CBCPAD", "A256CBCPAD".
    :type algorithm: str or ~azure.keyvault.v7_2.models.JsonWebKeyEncryptionAlgorithm
    :param value: Required.
    :type value: bytes
    :param iv: Initialization vector for symmetric algorithms.
    :type iv: bytes
    :param aad: Additional data to authenticate but not encrypt/decrypt when using authenticated
     crypto algorithms.
    :type aad: bytes
    :param tag: The tag to authenticate when performing decryption with an authenticated algorithm.
    :type tag: bytes
    """

    _validation = {
        'algorithm': {'required': True},
        'value': {'required': True},
    }

    _attribute_map = {
        'algorithm': {'key': 'alg', 'type': 'str'},
        'value': {'key': 'value', 'type': 'base64'},
        'iv': {'key': 'iv', 'type': 'base64'},
        'aad': {'key': 'aad', 'type': 'base64'},
        'tag': {'key': 'tag', 'type': 'base64'},
    }

    def __init__(
        self,
        *,
        algorithm: Union[str, "JsonWebKeyEncryptionAlgorithm"],
        value: bytes,
        iv: Optional[bytes] = None,
        aad: Optional[bytes] = None,
        tag: Optional[bytes] = None,
        **kwargs
    ):
        super(KeyOperationsParameters, self).__init__(**kwargs)
        self.algorithm = algorithm
        self.value = value
        self.iv = iv
        self.aad = aad
        self.tag = tag


class KeyProperties(msrest.serialization.Model):
    """Properties of the key pair backing a certificate.

    :param key_type: The type of key pair to be used for the certificate. Possible values include:
     "EC", "EC-HSM", "RSA", "RSA-HSM", "oct", "oct-HSM".
    :type key_type: str or ~azure.keyvault.v7_2.models.JsonWebKeyType
    :param key_size: The key size in bits. For example: 2048, 3072, or 4096 for RSA.
    :type key_size: int
    :param reuse_key: Indicates if the same key pair will be used on certificate renewal.
    :type reuse_key: bool
    :param curve: Elliptic curve name. For valid values, see JsonWebKeyCurveName. Possible values
     include: "P-256", "P-384", "P-521", "P-256K".
    :type curve: str or ~azure.keyvault.v7_2.models.JsonWebKeyCurveName
    """

    _attribute_map = {
        'key_type': {'key': 'kty', 'type': 'str'},
        'key_size': {'key': 'key_size', 'type': 'int'},
        'reuse_key': {'key': 'reuse_key', 'type': 'bool'},
        'curve': {'key': 'crv', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        key_type: Optional[Union[str, "JsonWebKeyType"]] = None,
        key_size: Optional[int] = None,
        reuse_key: Optional[bool] = None,
        curve: Optional[Union[str, "JsonWebKeyCurveName"]] = None,
        **kwargs
    ):
        super(KeyProperties, self).__init__(**kwargs)
        self.key_type = key_type
        self.key_size = key_size
        self.reuse_key = reuse_key
        self.curve = curve


class KeyRestoreParameters(msrest.serialization.Model):
    """The key restore parameters.

    All required parameters must be populated in order to send to Azure.

    :param key_bundle_backup: Required. The backup blob associated with a key bundle.
    :type key_bundle_backup: bytes
    """

    _validation = {
        'key_bundle_backup': {'required': True},
    }

    _attribute_map = {
        'key_bundle_backup': {'key': 'value', 'type': 'base64'},
    }

    def __init__(
        self,
        *,
        key_bundle_backup: bytes,
        **kwargs
    ):
        super(KeyRestoreParameters, self).__init__(**kwargs)
        self.key_bundle_backup = key_bundle_backup


class KeySignParameters(msrest.serialization.Model):
    """The key operations parameters.

    All required parameters must be populated in order to send to Azure.

    :param algorithm: Required. The signing/verification algorithm identifier. For more information
     on possible algorithm types, see JsonWebKeySignatureAlgorithm. Possible values include:
     "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "RSNULL", "ES256", "ES384", "ES512",
     "ES256K".
    :type algorithm: str or ~azure.keyvault.v7_2.models.JsonWebKeySignatureAlgorithm
    :param value: Required.
    :type value: bytes
    """

    _validation = {
        'algorithm': {'required': True},
        'value': {'required': True},
    }

    _attribute_map = {
        'algorithm': {'key': 'alg', 'type': 'str'},
        'value': {'key': 'value', 'type': 'base64'},
    }

    def __init__(
        self,
        *,
        algorithm: Union[str, "JsonWebKeySignatureAlgorithm"],
        value: bytes,
        **kwargs
    ):
        super(KeySignParameters, self).__init__(**kwargs)
        self.algorithm = algorithm
        self.value = value


class KeyUpdateParameters(msrest.serialization.Model):
    """The key update parameters.

    :param key_ops: Json web key operations. For more information on possible key operations, see
     JsonWebKeyOperation.
    :type key_ops: list[str or ~azure.keyvault.v7_2.models.JsonWebKeyOperation]
    :param key_attributes: The attributes of a key managed by the key vault service.
    :type key_attributes: ~azure.keyvault.v7_2.models.KeyAttributes
    :param tags: A set of tags. Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'key_ops': {'key': 'key_ops', 'type': '[str]'},
        'key_attributes': {'key': 'attributes', 'type': 'KeyAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        *,
        key_ops: Optional[List[Union[str, "JsonWebKeyOperation"]]] = None,
        key_attributes: Optional["KeyAttributes"] = None,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(KeyUpdateParameters, self).__init__(**kwargs)
        self.key_ops = key_ops
        self.key_attributes = key_attributes
        self.tags = tags


class KeyVaultError(msrest.serialization.Model):
    """The key vault error exception.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar error: The key vault server error.
    :vartype error: ~azure.keyvault.v7_2.models.Error
    """

    _validation = {
        'error': {'readonly': True},
    }

    _attribute_map = {
        'error': {'key': 'error', 'type': 'Error'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(KeyVaultError, self).__init__(**kwargs)
        self.error = None


class KeyVerifyParameters(msrest.serialization.Model):
    """The key verify parameters.

    All required parameters must be populated in order to send to Azure.

    :param algorithm: Required. The signing/verification algorithm. For more information on
     possible algorithm types, see JsonWebKeySignatureAlgorithm. Possible values include: "PS256",
     "PS384", "PS512", "RS256", "RS384", "RS512", "RSNULL", "ES256", "ES384", "ES512", "ES256K".
    :type algorithm: str or ~azure.keyvault.v7_2.models.JsonWebKeySignatureAlgorithm
    :param digest: Required. The digest used for signing.
    :type digest: bytes
    :param signature: Required. The signature to be verified.
    :type signature: bytes
    """

    _validation = {
        'algorithm': {'required': True},
        'digest': {'required': True},
        'signature': {'required': True},
    }

    _attribute_map = {
        'algorithm': {'key': 'alg', 'type': 'str'},
        'digest': {'key': 'digest', 'type': 'base64'},
        'signature': {'key': 'value', 'type': 'base64'},
    }

    def __init__(
        self,
        *,
        algorithm: Union[str, "JsonWebKeySignatureAlgorithm"],
        digest: bytes,
        signature: bytes,
        **kwargs
    ):
        super(KeyVerifyParameters, self).__init__(**kwargs)
        self.algorithm = algorithm
        self.digest = digest
        self.signature = signature


class KeyVerifyResult(msrest.serialization.Model):
    """The key verify result.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar value: True if the signature is verified, otherwise false.
    :vartype value: bool
    """

    _validation = {
        'value': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': 'bool'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(KeyVerifyResult, self).__init__(**kwargs)
        self.value = None
