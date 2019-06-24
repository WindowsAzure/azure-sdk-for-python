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


class QuotaBaseProperties(Model):
    """The properties for Quota update or retrieval.

    :param id: Specifies the resource ID.
    :type id: str
    :param type: Specifies the resource type.
    :type type: str
    :param limit: Limit. The maximum permitted quota of the resource.
    :type limit: long
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'limit': {'key': 'limit', 'type': 'long'},
    }

    def __init__(self, **kwargs):
        super(QuotaBaseProperties, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.type = kwargs.get('type', None)
        self.limit = kwargs.get('limit', None)
