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

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Specifies the resource ID.
    :vartype id: str
    :ivar type: Specifies the resource type.
    :vartype type: str
    :param quota: Quota. The workspace level quota.
    :type quota: int
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'quota': {'key': 'quota', 'type': 'int'},
    }

    def __init__(self, *, quota: int=None, **kwargs) -> None:
        super(QuotaBaseProperties, self).__init__(**kwargs)
        self.id = None
        self.type = None
        self.quota = quota
