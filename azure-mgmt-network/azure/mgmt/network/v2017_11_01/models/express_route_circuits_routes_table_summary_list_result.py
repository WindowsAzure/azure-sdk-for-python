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


class ExpressRouteCircuitsRoutesTableSummaryListResult(Model):
    """Response for ListRoutesTable associated with the Express Route Circuits
    API.

    :param value: A list of the routes table.
    :type value:
     list[~azure.mgmt.network.v2017_11_01.models.ExpressRouteCircuitRoutesTableSummary]
    :param next_link: The URL to get the next set of results.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ExpressRouteCircuitRoutesTableSummary]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self, value=None, next_link=None):
        super(ExpressRouteCircuitsRoutesTableSummaryListResult, self).__init__()
        self.value = value
        self.next_link = next_link
