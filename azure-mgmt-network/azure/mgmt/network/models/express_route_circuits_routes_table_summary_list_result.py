# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ExpressRouteCircuitsRoutesTableSummaryListResult(Model):
    """
    Response for ListRoutesTable associated with the Express Route Circuits Api

    :param value: Gets List of RoutesTable
    :type value: list of :class:`ExpressRouteCircuitRoutesTableSummary
     <networkmanagementclient.models.ExpressRouteCircuitRoutesTableSummary>`
    :param next_link: Gets the URL to get the next set of results.
    :type next_link: str
    """ 

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ExpressRouteCircuitRoutesTableSummary]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self, value=None, next_link=None):
        self.value = value
        self.next_link = next_link
