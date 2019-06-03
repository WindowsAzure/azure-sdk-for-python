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

from .delivery_rule_condition_py3 import DeliveryRuleCondition


class DeliveryRulePostArgsCondition(DeliveryRuleCondition):
    """Defines the PostArgs condition for the delivery rule.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Constant filled by server.
    :type name: str
    :param parameters: Required. Defines the parameters for the condition.
    :type parameters: ~azure.mgmt.cdn.models.PostArgsMatchConditionParameters
    """

    _validation = {
        'name': {'required': True},
        'parameters': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': 'PostArgsMatchConditionParameters'},
    }

    def __init__(self, *, parameters, **kwargs) -> None:
        super(DeliveryRulePostArgsCondition, self).__init__(**kwargs)
        self.parameters = parameters
        self.name = 'PostArgs'
