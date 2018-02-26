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


class IpFilterRule(Model):
    """The IP filter rules for the IoT hub.

    :param filter_name: The name of the IP filter rule.
    :type filter_name: str
    :param action: The desired action for requests captured by this rule.
     Possible values include: 'Accept', 'Reject'
    :type action: str or ~azure.mgmt.iothub.models.IpFilterActionType
    :param ip_mask: A string that contains the IP address range in CIDR
     notation for the rule.
    :type ip_mask: str
    """

    _validation = {
        'filter_name': {'required': True},
        'action': {'required': True},
        'ip_mask': {'required': True},
    }

    _attribute_map = {
        'filter_name': {'key': 'filterName', 'type': 'str'},
        'action': {'key': 'action', 'type': 'IpFilterActionType'},
        'ip_mask': {'key': 'ipMask', 'type': 'str'},
    }

    def __init__(self, filter_name, action, ip_mask):
        super(IpFilterRule, self).__init__()
        self.filter_name = filter_name
        self.action = action
        self.ip_mask = ip_mask
