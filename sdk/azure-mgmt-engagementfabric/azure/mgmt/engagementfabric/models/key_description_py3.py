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


class KeyDescription(Model):
    """The description of the EngagementFabric account key.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: The name of the key
    :vartype name: str
    :ivar rank: The rank of the key. Possible values include: 'PrimaryKey',
     'SecondaryKey'
    :vartype rank: str or ~azure.mgmt.engagementfabric.models.KeyRank
    :ivar value: The value of the key
    :vartype value: str
    """

    _validation = {
        'name': {'readonly': True},
        'rank': {'readonly': True},
        'value': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'rank': {'key': 'rank', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(KeyDescription, self).__init__(**kwargs)
        self.name = None
        self.rank = None
        self.value = None
