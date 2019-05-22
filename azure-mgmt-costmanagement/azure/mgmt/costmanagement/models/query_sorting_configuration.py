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


class QuerySortingConfiguration(Model):
    """The configuration for sorting in the query.

    :param query_sorting_direction: The sorting direction. Possible values
     include: 'Ascending', 'Descending'
    :type query_sorting_direction: str or
     ~azure.mgmt.costmanagement.models.SortDirection
    :param name: The name of the column to use in sorting.
    :type name: str
    """

    _attribute_map = {
        'query_sorting_direction': {'key': 'querySortingDirection', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(QuerySortingConfiguration, self).__init__(**kwargs)
        self.query_sorting_direction = kwargs.get('query_sorting_direction', None)
        self.name = kwargs.get('name', None)
