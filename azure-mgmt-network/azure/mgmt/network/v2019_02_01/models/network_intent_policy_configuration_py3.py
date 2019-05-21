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


class NetworkIntentPolicyConfiguration(Model):
    """Details of NetworkIntentPolicyConfiguration for
    PrepareNetworkPoliciesRequest.

    :param network_intent_policy_name: The name of the Network Intent Policy
     for storing in target subscription.
    :type network_intent_policy_name: str
    :param source_network_intent_policy: Source network intent policy.
    :type source_network_intent_policy:
     ~azure.mgmt.network.v2019_02_01.models.NetworkIntentPolicy
    """

    _attribute_map = {
        'network_intent_policy_name': {'key': 'networkIntentPolicyName', 'type': 'str'},
        'source_network_intent_policy': {'key': 'sourceNetworkIntentPolicy', 'type': 'NetworkIntentPolicy'},
    }

    def __init__(self, *, network_intent_policy_name: str=None, source_network_intent_policy=None, **kwargs) -> None:
        super(NetworkIntentPolicyConfiguration, self).__init__(**kwargs)
        self.network_intent_policy_name = network_intent_policy_name
        self.source_network_intent_policy = source_network_intent_policy
