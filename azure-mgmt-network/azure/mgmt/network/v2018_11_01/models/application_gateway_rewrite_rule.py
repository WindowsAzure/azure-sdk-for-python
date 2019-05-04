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


class ApplicationGatewayRewriteRule(Model):
    """Rewrite rule of an application gateway.

    :param name: Name of the rewrite rule that is unique within an Application
     Gateway.
    :type name: str
    :param action_set: Set of actions to be done as part of the rewrite Rule.
    :type action_set:
     ~azure.mgmt.network.v2018_11_01.models.ApplicationGatewayRewriteRuleActionSet
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'action_set': {'key': 'actionSet', 'type': 'ApplicationGatewayRewriteRuleActionSet'},
    }

    def __init__(self, **kwargs):
        super(ApplicationGatewayRewriteRule, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.action_set = kwargs.get('action_set', None)
