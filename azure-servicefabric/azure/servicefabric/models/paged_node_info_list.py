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


class PagedNodeInfoList(Model):
    """The list of nodes in the cluster. The list is paged when all of the results
    cannot fit in a single message. The next set of results can be obtained by
    executing the same query with the continuation token provided in this list.

    :param continuation_token:
    :type continuation_token: str
    :param items:
    :type items: list[~azure.servicefabric.models.NodeInfo]
    """

    _attribute_map = {
        'continuation_token': {'key': 'ContinuationToken', 'type': 'str'},
        'items': {'key': 'Items', 'type': '[NodeInfo]'},
    }

    def __init__(self, continuation_token=None, items=None):
        super(PagedNodeInfoList, self).__init__()
        self.continuation_token = continuation_token
        self.items = items
