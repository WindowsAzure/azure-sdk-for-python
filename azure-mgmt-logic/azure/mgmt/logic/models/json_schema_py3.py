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


class JsonSchema(Model):
    """The JSON schema.

    :param title: The JSON title.
    :type title: str
    :param content: The JSON content.
    :type content: str
    """

    _attribute_map = {
        'title': {'key': 'title', 'type': 'str'},
        'content': {'key': 'content', 'type': 'str'},
    }

    def __init__(self, *, title: str=None, content: str=None, **kwargs) -> None:
        super(JsonSchema, self).__init__(**kwargs)
        self.title = title
        self.content = content
