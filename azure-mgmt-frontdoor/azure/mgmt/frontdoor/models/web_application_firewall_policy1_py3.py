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

from .resource_py3 import Resource


class WebApplicationFirewallPolicy1(Resource):
    """Defines web application firewall policy.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param policy_settings: Describes  policySettings for policy
    :type policy_settings: ~azure.mgmt.frontdoor.models.PolicySettings
    :param custom_rules: Describes custom rules inside the policy
    :type custom_rules: ~azure.mgmt.frontdoor.models.CustomRules
    :param managed_rules: Describes managed rules inside the policy
    :type managed_rules: ~azure.mgmt.frontdoor.models.ManagedRuleSets
    :ivar provisioning_state: Provisioning state of the
     WebApplicationFirewallPolicy.
    :vartype provisioning_state: str
    :ivar resource_state: Resource status of the policy. Possible values
     include: 'Creating', 'Enabling', 'Enabled', 'Disabling', 'Disabled',
     'Deleting'
    :vartype resource_state: str or
     ~azure.mgmt.frontdoor.models.WebApplicationFirewallPolicy
    :param etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :type etag: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'resource_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'policy_settings': {'key': 'properties.policySettings', 'type': 'PolicySettings'},
        'custom_rules': {'key': 'properties.customRules', 'type': 'CustomRules'},
        'managed_rules': {'key': 'properties.managedRules', 'type': 'ManagedRuleSets'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'resource_state': {'key': 'properties.resourceState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, tags=None, policy_settings=None, custom_rules=None, managed_rules=None, etag: str=None, **kwargs) -> None:
        super(WebApplicationFirewallPolicy1, self).__init__(location=location, tags=tags, **kwargs)
        self.policy_settings = policy_settings
        self.custom_rules = custom_rules
        self.managed_rules = managed_rules
        self.provisioning_state = None
        self.resource_state = None
        self.etag = etag
