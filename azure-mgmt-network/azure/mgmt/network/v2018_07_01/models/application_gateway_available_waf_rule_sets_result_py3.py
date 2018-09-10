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


class ApplicationGatewayAvailableWafRuleSetsResult(Model):
    """Response for ApplicationGatewayAvailableWafRuleSets API service call.

    :param value: The list of application gateway rule sets.
    :type value:
     list[~azure.mgmt.network.v2018_07_01.models.ApplicationGatewayFirewallRuleSet]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ApplicationGatewayFirewallRuleSet]'},
    }

    def __init__(self, *, value=None, **kwargs) -> None:
        super(ApplicationGatewayAvailableWafRuleSetsResult, self).__init__(**kwargs)
        self.value = value
