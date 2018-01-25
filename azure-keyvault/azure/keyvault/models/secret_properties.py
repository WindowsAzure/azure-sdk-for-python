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


class SecretProperties(Model):
    """Properties of the key backing a certificate.

    :param content_type: The media type (MIME type).
    :type content_type: str
    """

    _attribute_map = {
        'content_type': {'key': 'contentType', 'type': 'str'},
    }

    def __init__(self, content_type=None):
        super(SecretProperties, self).__init__()
        self.content_type = content_type
