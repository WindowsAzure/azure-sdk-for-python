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

from .sub_resource import SubResource


class RoutingRule(SubResource):
    """A routing rule represents a specification for traffic to treat and where to
    send it, along with health probe information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param frontend_endpoints: Frontend endpoints associated with this rule
    :type frontend_endpoints: list[~azure.mgmt.frontdoor.models.SubResource]
    :param accepted_protocols: Protocol schemes to match for this rule
    :type accepted_protocols: list[str or
     ~azure.mgmt.frontdoor.models.FrontDoorProtocol]
    :param patterns_to_match: The route patterns of the rule.
    :type patterns_to_match: list[str]
    :param enabled_state: Whether to enable use of this rule. Permitted values
     are 'Enabled' or 'Disabled'. Possible values include: 'Enabled',
     'Disabled'
    :type enabled_state: str or
     ~azure.mgmt.frontdoor.models.RoutingRuleEnabledState
    :param route_configuration: A reference to the routing configuration.
    :type route_configuration: ~azure.mgmt.frontdoor.models.RouteConfiguration
    :param resource_state: Resource status. Possible values include:
     'Creating', 'Enabling', 'Enabled', 'Disabling', 'Disabled', 'Deleting'
    :type resource_state: str or
     ~azure.mgmt.frontdoor.models.FrontDoorResourceState
    :param name: Resource name.
    :type name: str
    :ivar type: Resource type.
    :vartype type: str
    """

    _validation = {
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'frontend_endpoints': {'key': 'properties.frontendEndpoints', 'type': '[SubResource]'},
        'accepted_protocols': {'key': 'properties.acceptedProtocols', 'type': '[str]'},
        'patterns_to_match': {'key': 'properties.patternsToMatch', 'type': '[str]'},
        'enabled_state': {'key': 'properties.enabledState', 'type': 'str'},
        'route_configuration': {'key': 'properties.routeConfiguration', 'type': 'RouteConfiguration'},
        'resource_state': {'key': 'properties.resourceState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RoutingRule, self).__init__(**kwargs)
        self.frontend_endpoints = kwargs.get('frontend_endpoints', None)
        self.accepted_protocols = kwargs.get('accepted_protocols', None)
        self.patterns_to_match = kwargs.get('patterns_to_match', None)
        self.enabled_state = kwargs.get('enabled_state', None)
        self.route_configuration = kwargs.get('route_configuration', None)
        self.resource_state = kwargs.get('resource_state', None)
        self.name = kwargs.get('name', None)
        self.type = None
