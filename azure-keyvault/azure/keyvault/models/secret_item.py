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


class SecretItem(Model):
    """The secret item containing secret metadata.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Secret identifier.
    :type id: str
    :param attributes: The secret management attributes.
    :type attributes: :class:`SecretAttributes
     <azure.keyvault.models.SecretAttributes>`
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict
    :param content_type: Type of the secret value such as a password.
    :type content_type: str
    :ivar managed: True if the secret's lifetime is managed by key vault. If
     this is a key backing a certificate, then managed will be true.
    :vartype managed: bool
    """

    _validation = {
        'managed': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'attributes': {'key': 'attributes', 'type': 'SecretAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'content_type': {'key': 'contentType', 'type': 'str'},
        'managed': {'key': 'managed', 'type': 'bool'},
    }

    def __init__(self, id=None, attributes=None, tags=None, content_type=None):
        self.id = id
        self.attributes = attributes
        self.tags = tags
        self.content_type = content_type
        self.managed = None
