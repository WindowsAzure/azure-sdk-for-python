# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class SecretBundle(Model):
    """A secret consisting of a value, id and its attributes.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param value: The secret value.
    :type value: str
    :param id: The secret id.
    :type id: str
    :param content_type: The content type of the secret.
    :type content_type: str
    :param attributes: The secret management attributes.
    :type attributes: ~azure.keyvault.v7_0.models.SecretAttributes
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    :ivar kid: If this is a secret backing a KV certificate, then this field
     specifies the corresponding key backing the KV certificate.
    :vartype kid: str
    :ivar managed: True if the secret's lifetime is managed by key vault. If
     this is a secret backing a certificate, then managed will be true.
    :vartype managed: bool
    """

    _validation = {
        'kid': {'readonly': True},
        'managed': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'content_type': {'key': 'contentType', 'type': 'str'},
        'attributes': {'key': 'attributes', 'type': 'SecretAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'kid': {'key': 'kid', 'type': 'str'},
        'managed': {'key': 'managed', 'type': 'bool'},
    }

    def __init__(self, *, value: str=None, id: str=None, content_type: str=None, attributes=None, tags=None, **kwargs) -> None:
        super(SecretBundle, self).__init__(**kwargs)
        self.value = value
        self.id = id
        self.content_type = content_type
        self.attributes = attributes
        self.tags = tags
        self.kid = None
        self.managed = None
