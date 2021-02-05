# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import EncryptionAlgorithm, KeyWrapAlgorithm, SignatureAlgorithm


class EncryptionAlgorithmConfiguration():
    """An encryption algorithm, including parameters applicable to using it for encryption or decryption.
    """

    def __init__(self, algorithm, **kwargs):
        self.algorithm = algorithm
        self.iv = kwargs.pop("iv", None)
        self.authentication_tag = kwargs.pop("authentication_tag", None)
        self.additional_authenticated_data = kwargs.pop("additional_authenticated_data", None)

    @classmethod
    def rsa_oaep_encrypt(cls):
        return cls(EncryptionAlgorithm.rsa_oaep)

    @classmethod
    def rsa_oaep_256_encrypt(cls):
        return cls(EncryptionAlgorithm.rsa_oaep_256)

    @classmethod
    def rsa1_5_encrypt(cls):
        return cls(EncryptionAlgorithm.rsa1_5)

    @classmethod
    def a128_gcm_encrypt(cls, additional_authenticated_data=None):
        return cls(
            EncryptionAlgorithm.a128_gcm, additional_authenticated_data=additional_authenticated_data
        )

    @classmethod
    def a192_gcm_encrypt(cls, additional_authenticated_data=None):
        return cls(
            EncryptionAlgorithm.a192_gcm, additional_authenticated_data=additional_authenticated_data
        )

    @classmethod
    def a256_gcm_encrypt(cls, additional_authenticated_data=None):
        return cls(
            EncryptionAlgorithm.a256_gcm, additional_authenticated_data=additional_authenticated_data
        )

    @classmethod
    def a128_cbc_encrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a128_cbc, iv=iv)

    @classmethod
    def a192_cbc_encrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a192_cbc, iv=iv)

    @classmethod
    def a256_cbc_encrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a256_cbc, iv=iv)

    @classmethod
    def a128_cbcpad_encrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a128_cbcpad, iv=iv)

    @classmethod
    def a192_cbcpad_encrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a192_cbcpad, iv=iv)

    @classmethod
    def a256_cbcpad_encrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a256_cbcpad, iv=iv)

    @classmethod
    def rsa_oaep_decrypt(cls):
        return cls(EncryptionAlgorithm.rsa_oaep)

    @classmethod
    def rsa_oaep_256_decrypt(cls):
        return cls(EncryptionAlgorithm.rsa_oaep_256)

    @classmethod
    def rsa1_5_decrypt(cls):
        return cls(EncryptionAlgorithm.rsa1_5)

    @classmethod
    def a128_gcm_decrypt(cls, authentication_tag=None, additional_authenticated_data=None):
        return cls(
            EncryptionAlgorithm.a128_gcm,
            authentication_tag=authentication_tag,
            additional_authenticated_data=additional_authenticated_data
        )

    @classmethod
    def a192_gcm_decrypt(cls, authentication_tag=None, additional_authenticated_data=None):
        return cls(
            EncryptionAlgorithm.a192_gcm,
            authentication_tag=authentication_tag,
            additional_authenticated_data=additional_authenticated_data
        )

    @classmethod
    def a256_gcm_decrypt(cls, authentication_tag=None, additional_authenticated_data=None):
        return cls(
            EncryptionAlgorithm.a256_gcm,
            authentication_tag=authentication_tag,
            additional_authenticated_data=additional_authenticated_data
        )

    @classmethod
    def a128_cbc_decrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a128_cbc, iv=iv)

    @classmethod
    def a192_cbc_decrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a192_cbc, iv=iv)

    @classmethod
    def a256_cbc_decrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a256_cbc, iv=iv)

    @classmethod
    def a128_cbcpad_decrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a128_cbcpad, iv=iv)

    @classmethod
    def a192_cbcpad_decrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a192_cbcpad, iv=iv)

    @classmethod
    def a256_cbcpad_decrypt(cls, iv=None):
        return cls(EncryptionAlgorithm.a256_cbcpad, iv=iv)


class DecryptResult:
    """The result of a decrypt operation.

    :param str key_id: The encryption key's Key Vault identifier
    :param algorithm: The encryption algorithm used
    :type algorithm: ~azure.keyvault.keys.crypto.EncryptionAlgorithm
    :param bytes plaintext: The decrypted bytes
    """

    def __init__(self, key_id, algorithm, plaintext):
        # type: (str, EncryptionAlgorithm, bytes) -> None
        self.key_id = key_id
        self.algorithm = algorithm
        self.plaintext = plaintext


class EncryptResult:
    """The result of an encrypt operation.

    :param str key_id: The encryption key's Key Vault identifier
    :param algorithm: The encryption algorithm used
    :type algorithm: ~azure.keyvault.keys.crypto.EncryptionAlgorithm
    :param bytes ciphertext: The encrypted bytes
    :param bytes iv: Initialization vector for symmetric algorithms
    :param bytes authentication_tag: The tag to authenticate when performing decryption with an authenticated algorithm
    :param bytes additional_authenticated_data: Additional data to authenticate but not encrypt/decrypt when using an
        authenticated algorithm
    """

    def __init__(
        self, key_id, algorithm, ciphertext, iv=None, authentication_tag=None, additional_authenticated_data=None
    ):
        # type: (str, EncryptionAlgorithm, bytes, bytes, bytes, bytes) -> None
        self.key_id = key_id
        self.algorithm = algorithm
        self.ciphertext = ciphertext
        self.iv = iv
        self.tag = authentication_tag
        self.aad = additional_authenticated_data


class SignResult:
    """The result of a sign operation.

    :param str key_id: The signing key's Key Vault identifier
    :param algorithm: The signature algorithm used
    :type algorithm: ~azure.keyvault.keys.crypto.SignatureAlgorithm
    :param bytes signature:
    """

    def __init__(self, key_id, algorithm, signature):
        # type: (str, SignatureAlgorithm, bytes) -> None
        self.key_id = key_id
        self.algorithm = algorithm
        self.signature = signature


class VerifyResult:
    """The result of a verify operation.

    :param str key_id: The signing key's Key Vault identifier
    :param bool is_valid: Whether the signature is valid
    :param algorithm: The signature algorithm used
    :type algorithm: ~azure.keyvault.keys.crypto.SignatureAlgorithm
    """

    def __init__(self, key_id, is_valid, algorithm):
        # type: (str, bool, SignatureAlgorithm) -> None
        self.key_id = key_id
        self.is_valid = is_valid
        self.algorithm = algorithm


class UnwrapResult:
    """The result of an unwrap key operation.

    :param str key_id: Key encryption key's Key Vault identifier
    :param algorithm: The key wrap algorithm used
    :type algorithm: ~azure.keyvault.keys.crypto.KeyWrapAlgorithm
    :param bytes key: The unwrapped key
    """

    def __init__(self, key_id, algorithm, key):
        # type: (str, KeyWrapAlgorithm, bytes) -> None
        self.key_id = key_id
        self.algorithm = algorithm
        self.key = key


class WrapResult:
    """The result of a wrap key operation.

    :param str key_id: The wrapping key's Key Vault identifier
    :param algorithm: The key wrap algorithm used
    :type algorithm: ~azure.keyvault.keys.crypto.KeyWrapAlgorithm
    :param bytes encrypted_key: The encrypted key bytes
    """

    def __init__(self, key_id, algorithm, encrypted_key):
        # type: (str, KeyWrapAlgorithm, bytes) -> None
        self.key_id = key_id
        self.algorithm = algorithm
        self.encrypted_key = encrypted_key
