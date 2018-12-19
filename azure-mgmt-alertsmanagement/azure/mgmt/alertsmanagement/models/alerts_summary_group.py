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


class AlertsSummaryGroup(Model):
    """Group the result set.

    :param total: Total count of the result set.
    :type total: int
    :param smart_groups_count: Total count of the smart groups.
    :type smart_groups_count: int
    :param groupedby: Name of the field aggregated
    :type groupedby: str
    :param values: List of the items
    :type values:
     list[~azure.mgmt.alertsmanagement.models.AlertsSummaryGroupItem]
    """

    _attribute_map = {
        'total': {'key': 'total', 'type': 'int'},
        'smart_groups_count': {'key': 'smartGroupsCount', 'type': 'int'},
        'groupedby': {'key': 'groupedby', 'type': 'str'},
        'values': {'key': 'values', 'type': '[AlertsSummaryGroupItem]'},
    }

    def __init__(self, **kwargs):
        super(AlertsSummaryGroup, self).__init__(**kwargs)
        self.total = kwargs.get('total', None)
        self.smart_groups_count = kwargs.get('smart_groups_count', None)
        self.groupedby = kwargs.get('groupedby', None)
        self.values = kwargs.get('values', None)
