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


class Content(Model):
    """Content.

    All required parameters must be populated in order to send to Azure.

    :param content_value: Required. Content to evaluate for a job.
    :type content_value: str
    """

    _validation = {
        'content_value': {'required': True},
    }

    _attribute_map = {
        'content_value': {'key': 'ContentValue', 'type': 'str'},
    }

    def __init__(self, *, content_value: str, **kwargs) -> None:
        super(Content, self).__init__(**kwargs)
        self.content_value = content_value
