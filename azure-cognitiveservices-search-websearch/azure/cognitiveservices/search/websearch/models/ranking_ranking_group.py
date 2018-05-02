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


class RankingRankingGroup(Model):
    """Defines a search results group, such as mainline.

    All required parameters must be populated in order to send to Azure.

    :param items: Required. A list of search result items to display in the
     group.
    :type items:
     list[~azure.cognitiveservices.search.websearch.models.RankingRankingItem]
    """

    _validation = {
        'items': {'required': True},
    }

    _attribute_map = {
        'items': {'key': 'items', 'type': '[RankingRankingItem]'},
    }

    def __init__(self, **kwargs):
        super(RankingRankingGroup, self).__init__(**kwargs)
        self.items = kwargs.get('items', None)
