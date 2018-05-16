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

from .entity_health_state_chunk_list_py3 import EntityHealthStateChunkList


class ApplicationHealthStateChunkList(EntityHealthStateChunkList):
    """The list of application health state chunks in the cluster that respect the
    input filters in the chunk query. Returned by get cluster health state
    chunks query.

    :param total_count: Total number of entity health state objects that match
     the specified filters from the cluster health chunk query description.
    :type total_count: long
    :param items: The list of application health state chunks that respect the
     input filters in the chunk query.
    :type items: list[~azure.servicefabric.models.ApplicationHealthStateChunk]
    """

    _attribute_map = {
        'total_count': {'key': 'TotalCount', 'type': 'long'},
        'items': {'key': 'Items', 'type': '[ApplicationHealthStateChunk]'},
    }

    def __init__(self, *, total_count: int=None, items=None, **kwargs) -> None:
        super(ApplicationHealthStateChunkList, self).__init__(total_count=total_count, **kwargs)
        self.items = items
