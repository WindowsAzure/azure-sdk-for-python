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


class SecurityGroupNetworkInterface(Model):
    """Network interface and all its associated security rules.

    :param id: ID of the network interface.
    :type id: str
    :param security_rule_associations:
    :type security_rule_associations:
     ~azure.mgmt.network.v2017_06_01.models.SecurityRuleAssociations
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'security_rule_associations': {'key': 'securityRuleAssociations', 'type': 'SecurityRuleAssociations'},
    }

    def __init__(self, **kwargs):
        super(SecurityGroupNetworkInterface, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.security_rule_associations = kwargs.get('security_rule_associations', None)
