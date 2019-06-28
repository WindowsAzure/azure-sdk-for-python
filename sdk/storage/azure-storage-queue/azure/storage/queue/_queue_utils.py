# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
# pylint: disable=unused-argument

from base64 import b64encode, b64decode
from xml.sax.saxutils import escape as xml_escape
from xml.sax.saxutils import unescape as xml_unescape

import six
from azure.core.exceptions import ResourceExistsError, DecodeError

from ._shared.models import StorageErrorCode
from ._shared.utils import process_storage_error
from ._shared.encryption import _decrypt_queue_message, _encrypt_queue_message
from ._generated.models import StorageErrorException
from .models import QueueProperties, QueueMessage


def deserialize_metadata(response, obj, headers):
    raw_metadata = {k: v for k, v in response.headers.items() if k.startswith("x-ms-meta-")}
    return {k[10:]: v for k, v in raw_metadata.items()}


def deserialize_queue_properties(response, obj, headers):
    metadata = deserialize_metadata(response, obj, headers)
    queue_properties = QueueProperties(
        metadata=metadata,
        **headers
    )
    return queue_properties


def deserialize_queue_creation(response, obj, headers):
    if response.status_code == 204:
        error_code = StorageErrorCode.queue_already_exists
        error = ResourceExistsError(
            message="Queue already exists\nRequestId:{}\nTime:{}\nErrorCode:{}".format(
                headers['x-ms-request-id'],
                headers['Date'],
                error_code
            ),
            response=response)
        error.error_code = error_code
        error.additional_info = {}
        raise error
    return headers


class MessageEncodePolicy(object):

    def __init__(self):
        self.require_encryption = False
        self.key_encryption_key = None
        self.resolver = None

    def __call__(self, content):
        if content:
            content = self.encode(content)
            if self.key_encryption_key is not None:
                content = _encrypt_queue_message(content, self.key_encryption_key)
        return content

    def configure(self, require_encryption, key_encryption_key, resolver):
        self.require_encryption = require_encryption
        self.key_encryption_key = key_encryption_key
        self.resolver = resolver
        if self.require_encryption and not self.key_encryption_key:
            raise ValueError("Encryption required but no key was provided.")

    def encode(self, content):
        raise NotImplementedError("Must be implemented by child class.")


class MessageDecodePolicy(object):

    def __init__(self):
        self.require_encryption = False
        self.key_encryption_key = None
        self.resolver = None

    def __call__(self, response, obj, headers):
        for message in obj:
            if message.message_text in [None, "", b""]:
                continue
            content = message.message_text
            if (self.key_encryption_key is not None) or (self.resolver is not None):
                content = _decrypt_queue_message(
                    content, response,
                    self.require_encryption,
                    self.key_encryption_key,
                    self.resolver)
            message.message_text = self.decode(content, response)
        return obj

    def configure(self, require_encryption, key_encryption_key, resolver):
        self.require_encryption = require_encryption
        self.key_encryption_key = key_encryption_key
        self.resolver = resolver

    def decode(self, content, response):
        raise NotImplementedError("Must be implemented by child class.")


class TextBase64EncodePolicy(MessageEncodePolicy):

    def encode(self, content):
        if not isinstance(content, six.text_type):
            raise TypeError("Message content must be text for base 64 encoding.")
        return b64encode(content.encode('utf-8')).decode('utf-8')


class TextBase64DecodePolicy(MessageDecodePolicy):

    def decode(self, content, response):
        try:
            return b64decode(content.encode('utf-8')).decode('utf-8')
        except (ValueError, TypeError) as error:
            # ValueError for Python 3, TypeError for Python 2
            raise DecodeError(
                message="Message content is not valid base 64.",
                response=response,
                error=error)


class BinaryBase64EncodePolicy(MessageEncodePolicy):

    def encode(self, content):
        if not isinstance(content, six.binary_type):
            raise TypeError("Message content must be bytes for base 64 encoding.")
        return b64encode(content).decode('utf-8')


class BinaryBase64DecodePolicy(MessageDecodePolicy):

    def decode(self, content, response):
        try:
            return b64decode(content.encode('utf-8'))
        except (ValueError, TypeError) as error:
            # ValueError for Python 3, TypeError for Python 2
            raise DecodeError(
                message="Message content is not valid base 64.",
                response=response,
                error=error)


class TextXMLEncodePolicy(MessageEncodePolicy):

    def encode(self, content):
        if not isinstance(content, six.text_type):
            raise TypeError("Message content must be text for XML encoding.")
        return xml_escape(content)


class TextXMLDecodePolicy(MessageDecodePolicy):

    def decode(self, content, response):
        return xml_unescape(content)


class NoEncodePolicy(MessageEncodePolicy):

    def encode(self, content):
        return content


class NoDecodePolicy(MessageDecodePolicy):

    def decode(self, content, response):
        return content
