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


class SecurityRuleAssociations(Model):
    """All security rules associated with the network interface.

    :param network_interface_association:
    :type network_interface_association:
     ~azure.mgmt.network.v2018_10_01.models.NetworkInterfaceAssociation
    :param subnet_association:
    :type subnet_association:
     ~azure.mgmt.network.v2018_10_01.models.SubnetAssociation
    :param default_security_rules: Collection of default security rules of the
     network security group.
    :type default_security_rules:
     list[~azure.mgmt.network.v2018_10_01.models.SecurityRule]
    :param effective_security_rules: Collection of effective security rules.
    :type effective_security_rules:
     list[~azure.mgmt.network.v2018_10_01.models.EffectiveNetworkSecurityRule]
    """

    _attribute_map = {
        'network_interface_association': {'key': 'networkInterfaceAssociation', 'type': 'NetworkInterfaceAssociation'},
        'subnet_association': {'key': 'subnetAssociation', 'type': 'SubnetAssociation'},
        'default_security_rules': {'key': 'defaultSecurityRules', 'type': '[SecurityRule]'},
        'effective_security_rules': {'key': 'effectiveSecurityRules', 'type': '[EffectiveNetworkSecurityRule]'},
    }

    def __init__(self, **kwargs):
        super(SecurityRuleAssociations, self).__init__(**kwargs)
        self.network_interface_association = kwargs.get('network_interface_association', None)
        self.subnet_association = kwargs.get('subnet_association', None)
        self.default_security_rules = kwargs.get('default_security_rules', None)
        self.effective_security_rules = kwargs.get('effective_security_rules', None)
