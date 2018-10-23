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


class SecretUpdateParameters(Model):
    """The secret update parameters.

    :param content_type: Type of the secret value such as a password.
    :type content_type: str
    :param secret_attributes: The secret management attributes.
    :type secret_attributes: ~azure.keyvault.v7_0.models.SecretAttributes
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'content_type': {'key': 'contentType', 'type': 'str'},
        'secret_attributes': {'key': 'attributes', 'type': 'SecretAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(SecretUpdateParameters, self).__init__(**kwargs)
        self.content_type = kwargs.get('content_type', None)
        self.secret_attributes = kwargs.get('secret_attributes', None)
        self.tags = kwargs.get('tags', None)
