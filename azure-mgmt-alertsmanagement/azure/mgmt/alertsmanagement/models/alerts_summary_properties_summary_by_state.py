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

from .alerts_summary_by_state import AlertsSummaryByState


class AlertsSummaryPropertiesSummaryByState(AlertsSummaryByState):
    """Summary of alerts by state.

    :param new: Count of alerts with state 'New'
    :type new: int
    :param acknowledged: Count of alerts with state 'Acknowledged'
    :type acknowledged: int
    :param closed: Count of alerts with state 'Closed'
    :type closed: int
    """

    _attribute_map = {
        'new': {'key': 'new', 'type': 'int'},
        'acknowledged': {'key': 'acknowledged', 'type': 'int'},
        'closed': {'key': 'closed', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(AlertsSummaryPropertiesSummaryByState, self).__init__(**kwargs)
