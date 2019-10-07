# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from azure.core.exceptions import AzureError, HttpResponseError
from azure.core.tracing.decorator_async import distributed_trace_async
from azure.keyvault.keys.models import Key
from azure.keyvault.keys._shared import AsyncKeyVaultClientBase, parse_vault_id

from .. import DecryptResult, EncryptResult, SignResult, VerifyResult, UnwrapKeyResult, WrapKeyResult
from .._internal import EllipticCurveKey, RsaKey

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    # pylint:disable=unused-import
    from typing import Any, Optional, Union
    from azure.core.credentials import TokenCredential
    from .. import EncryptionAlgorithm, KeyWrapAlgorithm, SignatureAlgorithm
    from .._internal import Key as _Key


class CryptographyClient(AsyncKeyVaultClientBase):
    """
    Performs cryptographic operations using Azure Key Vault keys.

    :param key:
        Either a :class:`~azure.keyvault.keys.models.Key` instance as returned by
        :func:`~azure.keyvault.keys.aio.KeyClient.get_key`, or a string.
        If a string, the value must be the full identifier of an Azure Key Vault key with a version.
    :type key: str or :class:`~azure.keyvault.keys.models.Key`
    :param credential: An object which can provide an access token for the vault, such as a credential from
        :mod:`azure.identity.aio`

    Keyword arguments
        - **api_version** - version of the Key Vault API to use. Defaults to the most recent.

    Creating a ``CryptographyClient``:

    .. code-block:: python

        from azure.identity.aio import DefaultAzureCredential
        from azure.keyvault.keys.crypto.aio import CryptographyClient

        credential = DefaultAzureCredential()

        # create a CryptographyClient using a Key instance
        key = await key_client.get_key("mykey")
        crypto_client = CryptographyClient(key, credential)

        # or a Key's id, which must include a version
        key_id = "https://<your vault>.vault.azure.net/keys/mykey/fe4fdcab688c479a9aa80f01ffeac26"
        crypto_client = CryptographyClient(key_id, credential)

    You can also obtain a ``CryptographyClient`` from a :class:`~azure.keyvault.keys.aio.KeyClient`:

    .. code-block:: python

        from azure.identity.aio import DefaultAzureCredential
        from azure.keyvault.keys.aio import KeyClient

        credential = DefaultAzureCredential()
        key_client = KeyClient(vault_endpoint=<your vault url>, credential=credential)
        crypto_client = key_client.get_cryptography_client("mykey")

    """

    def __init__(self, key: "Union[Key, str]", credential: "TokenCredential", **kwargs: "**Any") -> None:
        if isinstance(key, Key):
            self._key = key
            self._key_id = parse_vault_id(key.id)
            self._allowed_ops = frozenset(self._key.key_material.key_ops)
        elif isinstance(key, str):
            self._key = None
            self._key_id = parse_vault_id(key)
            self._keys_get_forbidden = None  # type: Optional[bool]

            # will be replaced with actual permissions before any local operations are attempted, if we can get the key
            self._allowed_ops = frozenset()
        else:
            raise ValueError("'key' must be a Key instance or a key ID string including a version")

        if not self._key_id.version:
            raise ValueError("'key' must include a version")

        self._internal_key = None  # type: Optional[_Key]

        super(CryptographyClient, self).__init__(
            vault_endpoint=self._key_id.vault_endpoint, credential=credential, **kwargs
        )

    @property
    def key_id(self) -> str:
        """
        The full identifier of the client's key.

        :rtype: str
        """
        return "/".join(self._key_id)

    @distributed_trace_async
    async def get_key(self, **kwargs: "Any") -> "Optional[Key]":
        """
        Get the client's :class:`~azure.keyvault.keys.models.Key`.
        Can be `None`, if the client lacks keys/get permission.

        :rtype: :class:`~azure.keyvault.keys.models.Key` or None
        """

        if not (self._key or self._keys_get_forbidden):
            try:
                self._key = await self._client.get_key(
                    self._key_id.vault_endpoint, self._key_id.name, self._key_id.version, **kwargs
                )
                self._allowed_ops = frozenset(self._key.key_material.key_ops)
            except HttpResponseError as ex:
                # if we got a 403, we don't have keys/get permission and won't try to get the key again
                # (other errors may be transient)
                self._keys_get_forbidden = ex.status_code == 403
        return self._key

    async def _get_local_key(self, **kwargs: "Any") -> "Optional[_Key]":
        """Gets an object implementing local operations. Will be ``None``, if the client was instantiated with a key
        id and lacks keys/get permission."""

        if not self._internal_key:
            key = await self.get_key(**kwargs)
            if not key:
                return None

            if key.key_material.kty.lower().startswith("ec"):
                self._internal_key = EllipticCurveKey.from_jwk(key.key_material)
            else:
                self._internal_key = RsaKey.from_jwk(key.key_material)

        return self._internal_key

    @distributed_trace_async
    async def encrypt(self, algorithm: "EncryptionAlgorithm", plaintext: bytes, **kwargs: "Any") -> EncryptResult:
        # pylint:disable=line-too-long
        """
        Encrypt bytes using the client's key. Requires the keys/encrypt permission.

        This method encrypts only a single block of data, the size of which depends on the key and encryption algorithm.

        :param algorithm: encryption algorithm to use
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.EncryptionAlgorithm`
        :param bytes plaintext: bytes to encrypt
        :rtype: :class:`~azure.keyvault.keys.crypto.EncryptResult`

        Example:

        .. code-block:: python

            from azure.keyvault.keys.crypto import EncryptionAlgorithm

            # encrypt returns a tuple with the ciphertext and the metadata required to decrypt it
            key_id, algorithm, ciphertext, authentication_tag =
                await client.encrypt(EncryptionAlgorithm.rsa_oaep, b"plaintext")

        """

        local_key = await self._get_local_key(**kwargs)
        if local_key:
            if "encrypt" not in self._allowed_ops:
                raise AzureError("This client doesn't have 'keys/encrypt' permission")
            result = local_key.encrypt(plaintext, algorithm=algorithm.value)
        else:
            result = await self._client.encrypt(
                self._key_id.vault_endpoint, self._key_id.name, self._key_id.version, algorithm, plaintext, **kwargs
            ).result
        return EncryptResult(key_id=self.key_id, algorithm=algorithm, ciphertext=result, authentication_tag=None)

    @distributed_trace_async
    async def decrypt(self, algorithm: "EncryptionAlgorithm", ciphertext: bytes, **kwargs: "**Any") -> DecryptResult:
        """
        Decrypt a single block of encrypted data using the client's key. Requires the keys/decrypt permission.

        This method decrypts only a single block of data, the size of which depends on the key and encryption algorithm.

        :param algorithm: encryption algorithm to use
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.EncryptionAlgorithm`
        :param bytes ciphertext: encrypted bytes to decrypt
        :rtype: :class:`~azure.keyvault.keys.crypto.DecryptResult`

        Example:

        .. code-block:: python

            from azure.keyvault.keys.crypto import EncryptionAlgorithm

            result = await client.decrypt(EncryptionAlgorithm.rsa_oaep, ciphertext)
            print(result.decrypted_bytes)

        """

        authentication_data = kwargs.pop("authentication_data", None)
        authentication_tag = kwargs.pop("authentication_tag", None)
        if authentication_data and not authentication_tag:
            raise ValueError("'authentication_tag' is required when 'authentication_data' is specified")

        result = await self._client.decrypt(
            vault_base_url=self._key_id.vault_endpoint,
            key_name=self._key_id.name,
            key_version=self._key_id.version,
            algorithm=algorithm,
            value=ciphertext,
            **kwargs
        )
        return DecryptResult(decrypted_bytes=result.result)

    @distributed_trace_async
    async def wrap_key(self, algorithm: "KeyWrapAlgorithm", key: bytes, **kwargs: "Any") -> WrapKeyResult:
        """
        Wrap a key with the client's key. Requires the keys/wrapKey permission.

        :param algorithm: wrapping algorithm to use
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.KeyWrapAlgorithm`
        :param bytes key: key to wrap
        :rtype: :class:`~azure.keyvault.keys.crypto.WrapKeyResult`

        Example:

        .. code-block:: python

            from azure.keyvault.keys.crypto import KeyWrapAlgorithm

            # wrap returns a tuple with the wrapped bytes and the metadata required to unwrap the key
            key_id, wrap_algorithm, wrapped_bytes = await client.wrap_key(KeyWrapAlgorithm.rsa_oaep, key_bytes)

        """

        local_key = await self._get_local_key(**kwargs)
        if local_key:
            if "wrapKey" not in self._allowed_ops:
                raise AzureError("This client doesn't have 'keys/wrapKey' permission")
            result = local_key.wrap_key(key, algorithm=algorithm.value)
        else:
            result = await self._client.wrap_key(
                self._key_id.vault_endpoint,
                self._key_id.name,
                self._key_id.version,
                algorithm=algorithm,
                value=key,
                **kwargs
            ).result
        return WrapKeyResult(key_id=self.key_id, algorithm=algorithm, encrypted_key=result)

    @distributed_trace_async
    async def unwrap_key(self, algorithm: "KeyWrapAlgorithm", encrypted_key: bytes, **kwargs: "Any") -> UnwrapKeyResult:
        """
        Unwrap a key previously wrapped with the client's key. Requires the keys/unwrapKey permission.

        :param algorithm: wrapping algorithm to use
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.KeyWrapAlgorithm`
        :param bytes encrypted_key: the wrapped key
        :rtype: :class:`~azure.keyvault.keys.crypto.UnwrapKeyResult`

        Example:

        .. code-block:: python

            from azure.keyvault.keys.crypto import KeyWrapAlgorithm

            result = await client.unwrap_key(KeyWrapAlgorithm.rsa_oaep, wrapped_bytes)
            unwrapped_bytes = result.unwrapped_bytes

        """

        result = await self._client.unwrap_key(
            self._key_id.vault_endpoint,
            self._key_id.name,
            self._key_id.version,
            algorithm=algorithm,
            value=encrypted_key,
            **kwargs
        )
        return UnwrapKeyResult(unwrapped_bytes=result.result)

    @distributed_trace_async
    async def sign(self, algorithm: "SignatureAlgorithm", digest: bytes, **kwargs: "**Any") -> SignResult:
        """
        Create a signature from a digest using the client's key. Requires the keys/sign permission.

        :param algorithm: signing algorithm
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.SignatureAlgorithm`
        :param bytes digest: hashed bytes to sign
        :rtype: :class:`~azure.keyvault.keys.crypto.SignResult`

        Example:

        .. code-block:: python

            import hashlib
            from azure.keyvault.keys.crypto import SignatureAlgorithm

            digest = hashlib.sha256(b"plaintext").digest()

            # sign returns a tuple with the signature and the metadata required to verify it
            key_id, algorithm, signature = await client.sign(SignatureAlgorithm.rs256, digest)

        """

        result = await self._client.sign(
            vault_base_url=self._key_id.vault_endpoint,
            key_name=self._key_id.name,
            key_version=self._key_id.version,
            algorithm=algorithm,
            value=digest,
            **kwargs
        )
        return SignResult(key_id=self.key_id, algorithm=algorithm, signature=result.result)

    @distributed_trace_async
    async def verify(
        self, algorithm: "SignatureAlgorithm", digest: bytes, signature: bytes, **kwargs: "**Any"
    ) -> VerifyResult:
        """
        Verify a signature using the client's key. Requires the keys/verify permission.

        :param algorithm: verification algorithm
        :type algorithm: :class:`~azure.keyvault.keys.crypto.enums.SignatureAlgorithm`
        :param bytes digest:
        :param bytes signature:
        :rtype: :class:`~azure.keyvault.keys.crypto.VerifyResult`

        Example:

        .. code-block:: python

            from azure.keyvault.keys.crypto import SignatureAlgorithm

            verified = await client.verify(SignatureAlgorithm.rs256, digest, signature)
            assert verified.result is True

        """

        local_key = await self._get_local_key(**kwargs)
        if local_key:
            if "verify" not in self._allowed_ops:
                raise AzureError("This client doesn't have 'keys/verify' permission")
            result = local_key.verify(digest, signature, algorithm=algorithm.value)
        else:
            result = await self._client.verify(
                vault_base_url=self._key_id.vault_endpoint,
                key_name=self._key_id.name,
                key_version=self._key_id.version,
                algorithm=algorithm,
                digest=digest,
                signature=signature,
                **kwargs
            ).value
        return VerifyResult(result=result)
