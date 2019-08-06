# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    # pylint:disable=unused-import
    from typing import Any, Optional, Union
    from azure.core.credentials import TokenCredential
    from . import EncryptionAlgorithm, KeyWrapAlgorithm, SignatureAlgorithm

from azure.core.exceptions import HttpResponseError
import six

from . import DecryptResult, EncryptResult, SignResult, VerifyResult, UnwrapKeyResult, WrapKeyResult
from ..models import Key
from .._shared import KeyVaultClientBase, parse_vault_id


class CryptographyClient(KeyVaultClientBase):
    """
    Performs cryptographic operations using Azure Key Vault keys.

    :param key:
        Either a :class:`~azure.keyvault.keys.models.Key` instance as returned by
        :func:`~azure.keyvault.keys.KeyClient.get_key`, or a string.
        If a string, the value must be the full identifier of an Azure Key Vault key with a version.
    :type key: str or :class:`~azure.keyvault.keys.models.Key`
    :param credential: An object which can provide an access token for the vault, such as a credential from
        :mod:`azure.identity`

    Keyword arguments
        - *api_version* - version of the Key Vault API to use. Defaults to the most recent.
    """

    def __init__(self, key, credential, **kwargs):
        # type: (Union[Key, str], TokenCredential, Any) -> None

        if isinstance(key, Key):
            self._key = key
            self._key_id = parse_vault_id(key.id)
        elif isinstance(key, six.text_type):
            self._key = None
            self._key_id = parse_vault_id(key)
            self._get_key_forbidden = None  # type: Optional[bool]
        else:
            raise ValueError("'key' must be a Key instance or a key ID string including a version")

        if not self._key_id.version:
            raise ValueError("'key' must include a version")

        super(CryptographyClient, self).__init__(vault_url=self._key_id.vault_url, credential=credential, **kwargs)

    @property
    def key_id(self):
        # type: () -> str
        """
        The full identifier of the client's key.

        :rtype: str
        """
        return "/".join(self._key_id)

    @property
    def key(self):
        # type: () -> Optional[Key]
        """
        The client's :class:`~azure.keyvault.keys.models.Key`.
        Can be `None`, if the client lacks keys/get permission.

        :rtype: :class:`~azure.keyvault.keys.models.Key`
        """

        if not (self._key or self._get_key_forbidden):
            try:
                self._key = self._client.get_key(self._key_id.vault_url, self._key_id.name, self._key_id.version)
            except HttpResponseError as ex:
                self._get_key_forbidden = ex.status_code == 403
        return self._key

    def encrypt(self, plaintext, algorithm, **kwargs):
        # type: (bytes, EncryptionAlgorithm, Any) -> EncryptResult
        """
        Encrypt bytes using the client's key. Requires the keys/encrypt permission.

        This method encrypts only a single block of data, the size of which depends on the key and encryption algorithm.

        :param bytes plaintext: bytes to encrypt
        :param algorithm: encryption algorithm to use
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.EncryptionAlgorithm`
        :rtype: :class:`~azure.keyvault.keys.crypto.EncryptResult`
        """

        result = self._client.encrypt(
            self._key_id.vault_url, self._key_id.name, self._key_id.version, algorithm, plaintext, **kwargs
        )
        return EncryptResult(key_id=self.key_id, algorithm=algorithm, ciphertext=result.result, authentication_tag=None)

    def decrypt(self, ciphertext, algorithm, **kwargs):
        # type: (bytes, EncryptionAlgorithm, Any) -> DecryptResult
        """
        Decrypt a single block of encrypted data using the client's key. Requires the keys/decrypt permission.

        This method decrypts only a single block of data, the size of which depends on the key and encryption algorithm.

        :param bytes ciphertext: encrypted bytes to decrypt
        :param algorithm: encryption algorithm to use
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.EncryptionAlgorithm`
        :rtype: :class:`~azure.keyvault.keys.crypto.DecryptResult`
        """

        authentication_data = kwargs.pop("authentication_data", None)
        authentication_tag = kwargs.pop("authentication_tag", None)
        if authentication_data and not authentication_tag:
            raise ValueError("'authentication_tag' is required when 'authentication_data' is specified")

        result = self._client.decrypt(
            self._key_id.vault_url, self._key_id.name, self._key_id.version, algorithm, ciphertext, **kwargs
        )
        return DecryptResult(decrypted_bytes=result.result)

    def wrap(self, key, algorithm, **kwargs):
        # type: (bytes, KeyWrapAlgorithm, Any) -> WrapKeyResult
        """
        Wrap a key with the client's key. Requires the keys/wrapKey permission.

        :param bytes key: key to wrap
        :param algorithm: wrapping algorithm to use
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.KeyWrapAlgorithm`
        :rtype: :class:`~azure.keyvault.keys.crypto.WrapKeyResult`
        """

        result = self._client.wrap_key(
            self._key_id.vault_url, self._key_id.name, self._key_id.version, algorithm=algorithm, value=key, **kwargs
        )
        return WrapKeyResult(key_id=self.key_id, algorithm=algorithm, encrypted_key=result.result)

    def unwrap(self, encrypted_key, algorithm, **kwargs):
        # type: (bytes, KeyWrapAlgorithm, Any) -> UnwrapKeyResult
        """
        Unwrap a key previously wrapped with the client's key. Requires the keys/unwrapKey permission.

        :param bytes encrypted_key: the wrapped key
        :param algorithm: wrapping algorithm to use
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.KeyWrapAlgorithm`
        :rtype: :class:`~azure.keyvault.keys.crypto.UnwrapKeyResult`
        """

        result = self._client.unwrap_key(
            self._key_id.vault_url,
            self._key_id.name,
            self._key_id.version,
            algorithm=algorithm,
            value=encrypted_key,
            **kwargs
        )
        return UnwrapKeyResult(unwrapped_bytes=result.result)

    def sign(self, digest, algorithm, **kwargs):
        # type: (bytes, SignatureAlgorithm, Any) -> SignResult
        """
        Create a signature from a digest using the client's key. Requires the keys/sign permission.

        :param bytes digest: hashed bytes to sign
        :param algorithm: signing algorithm
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.SignatureAlgorithm`
        :rtype: :class:`~azure.keyvault.keys.crypto.SignResult`
        """

        result = self._client.sign(
            self._key_id.vault_url, self._key_id.name, self._key_id.version, algorithm, digest, **kwargs
        )
        return SignResult(key_id=self.key_id, algorithm=algorithm, signature=result.result)

    def verify(self, digest, signature, algorithm, **kwargs):
        # type: (bytes, bytes, SignatureAlgorithm, Any) -> VerifyResult
        """
        Verify a signature using the client's key. Requires the keys/verify permission.

        :param bytes digest:
        :param bytes signature:
        :param algorithm: verification algorithm
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.SignatureAlgorithm`
        :rtype: :class:`~azure.keyvault.keys.crypto.VerifyResult`
        """

        result = self._client.verify(
            self._key_id.vault_url, self._key_id.name, self._key_id.version, algorithm, digest, signature, **kwargs
        )
        return VerifyResult(result=result.value)
