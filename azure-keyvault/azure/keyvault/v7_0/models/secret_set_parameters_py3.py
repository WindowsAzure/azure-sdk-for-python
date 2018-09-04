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


class SecretSetParameters(Model):
    """The secret set parameters.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. The value of the secret.
    :type value: str
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    :param content_type: Type of the secret value such as a password.
    :type content_type: str
    :param secret_attributes: The secret management attributes.
    :type secret_attributes: ~azure.keyvault.v7_0.models.SecretAttributes
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'content_type': {'key': 'contentType', 'type': 'str'},
        'secret_attributes': {'key': 'attributes', 'type': 'SecretAttributes'},
    }

    def __init__(self, *, value: str, tags=None, content_type: str=None, secret_attributes=None, **kwargs) -> None:
        super(SecretSetParameters, self).__init__(**kwargs)
        self.value = value
        self.tags = tags
        self.content_type = content_type
        self.secret_attributes = secret_attributes
