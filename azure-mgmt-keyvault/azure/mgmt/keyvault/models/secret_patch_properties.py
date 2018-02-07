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


class SecretPatchProperties(Model):
    """Properties of the secret.

    :param value: The value of the secret.
    :type value: str
    :param content_type: The content type of the secret.
    :type content_type: str
    :param attributes: The attributes of the secret.
    :type attributes: ~azure.mgmt.keyvault.models.SecretAttributes
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': 'str'},
        'content_type': {'key': 'contentType', 'type': 'str'},
        'attributes': {'key': 'attributes', 'type': 'SecretAttributes'},
    }

    def __init__(self, value=None, content_type=None, attributes=None):
        super(SecretPatchProperties, self).__init__()
        self.value = value
        self.content_type = content_type
        self.attributes = attributes
