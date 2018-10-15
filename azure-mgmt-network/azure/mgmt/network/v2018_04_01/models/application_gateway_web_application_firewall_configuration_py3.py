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


class ApplicationGatewayWebApplicationFirewallConfiguration(Model):
    """Application gateway web application firewall configuration.

    All required parameters must be populated in order to send to Azure.

    :param enabled: Required. Whether the web application firewall is enabled
     or not.
    :type enabled: bool
    :param firewall_mode: Required. Web application firewall mode. Possible
     values include: 'Detection', 'Prevention'
    :type firewall_mode: str or
     ~azure.mgmt.network.v2018_04_01.models.ApplicationGatewayFirewallMode
    :param rule_set_type: Required. The type of the web application firewall
     rule set. Possible values are: 'OWASP'.
    :type rule_set_type: str
    :param rule_set_version: Required. The version of the rule set type.
    :type rule_set_version: str
    :param disabled_rule_groups: The disabled rule groups.
    :type disabled_rule_groups:
     list[~azure.mgmt.network.v2018_04_01.models.ApplicationGatewayFirewallDisabledRuleGroup]
    :param request_body_check: Whether allow WAF to check request Body.
    :type request_body_check: bool
    :param max_request_body_size: Maxium request body size for WAF.
    :type max_request_body_size: int
    """

    _validation = {
        'enabled': {'required': True},
        'firewall_mode': {'required': True},
        'rule_set_type': {'required': True},
        'rule_set_version': {'required': True},
        'max_request_body_size': {'maximum': 128, 'minimum': 8},
    }

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'firewall_mode': {'key': 'firewallMode', 'type': 'str'},
        'rule_set_type': {'key': 'ruleSetType', 'type': 'str'},
        'rule_set_version': {'key': 'ruleSetVersion', 'type': 'str'},
        'disabled_rule_groups': {'key': 'disabledRuleGroups', 'type': '[ApplicationGatewayFirewallDisabledRuleGroup]'},
        'request_body_check': {'key': 'requestBodyCheck', 'type': 'bool'},
        'max_request_body_size': {'key': 'maxRequestBodySize', 'type': 'int'},
    }

    def __init__(self, *, enabled: bool, firewall_mode, rule_set_type: str, rule_set_version: str, disabled_rule_groups=None, request_body_check: bool=None, max_request_body_size: int=None, **kwargs) -> None:
        super(ApplicationGatewayWebApplicationFirewallConfiguration, self).__init__(**kwargs)
        self.enabled = enabled
        self.firewall_mode = firewall_mode
        self.rule_set_type = rule_set_type
        self.rule_set_version = rule_set_version
        self.disabled_rule_groups = disabled_rule_groups
        self.request_body_check = request_body_check
        self.max_request_body_size = max_request_body_size
