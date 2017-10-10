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


class PatchRouteFilterRule(SubResource):
    """Route Filter Rule Resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param access: The access type of the rule. Valid values are: 'Allow',
     'Deny'. Possible values include: 'Allow', 'Deny'
    :type access: str or ~azure.mgmt.network.v2017_09_01.models.Access
    :ivar route_filter_rule_type: The rule type of the rule. Valid value is:
     'Community'. Default value: "Community" .
    :vartype route_filter_rule_type: str
    :param communities: The collection for bgp community values to filter on.
     e.g. ['12076:5010','12076:5020']
    :type communities: list[str]
    :ivar provisioning_state: The provisioning state of the resource. Possible
     values are: 'Updating', 'Deleting', 'Succeeded' and 'Failed'.
    :vartype provisioning_state: str
    :ivar name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :vartype name: str
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    """

    _validation = {
        'access': {'required': True},
        'route_filter_rule_type': {'required': True, 'constant': True},
        'communities': {'required': True},
        'provisioning_state': {'readonly': True},
        'name': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'access': {'key': 'properties.access', 'type': 'str'},
        'route_filter_rule_type': {'key': 'properties.routeFilterRuleType', 'type': 'str'},
        'communities': {'key': 'properties.communities', 'type': '[str]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    route_filter_rule_type = "Community"

    def __init__(self, access, communities, id=None, tags=None):
        super(PatchRouteFilterRule, self).__init__(id=id)
        self.access = access
        self.communities = communities
        self.provisioning_state = None
        self.name = None
        self.etag = None
        self.tags = tags
