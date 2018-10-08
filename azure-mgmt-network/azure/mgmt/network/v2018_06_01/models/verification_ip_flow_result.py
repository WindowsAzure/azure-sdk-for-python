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


class VerificationIPFlowResult(Model):
    """Results of IP flow verification on the target resource.

    :param access: Indicates whether the traffic is allowed or denied.
     Possible values include: 'Allow', 'Deny'
    :type access: str or ~azure.mgmt.network.v2018_06_01.models.Access
    :param rule_name: Name of the rule. If input is not matched against any
     security rule, it is not displayed.
    :type rule_name: str
    """

    _attribute_map = {
        'access': {'key': 'access', 'type': 'str'},
        'rule_name': {'key': 'ruleName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(VerificationIPFlowResult, self).__init__(**kwargs)
        self.access = kwargs.get('access', None)
        self.rule_name = kwargs.get('rule_name', None)
