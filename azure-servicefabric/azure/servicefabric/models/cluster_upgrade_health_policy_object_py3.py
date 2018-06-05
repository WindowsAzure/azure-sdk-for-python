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


class ClusterUpgradeHealthPolicyObject(Model):
    """Defines a health policy used to evaluate the health of the cluster during a
    cluster upgrade.

    :param max_percent_delta_unhealthy_nodes: The maximum allowed percentage
     of nodes health degradation allowed during cluster upgrades. The delta is
     measured between the state of the nodes at the beginning of upgrade and
     the state of the nodes at the time of the health evaluation. The check is
     performed after every upgrade domain upgrade completion to make sure the
     global state of the cluster is within tolerated limits. The default value
     is 10%.
    :type max_percent_delta_unhealthy_nodes: int
    :param max_percent_upgrade_domain_delta_unhealthy_nodes: The maximum
     allowed percentage of upgrade domain nodes health degradation allowed
     during cluster upgrades. The delta is measured between the state of the
     upgrade domain nodes at the beginning of upgrade and the state of the
     upgrade domain nodes at the time of the health evaluation. The check is
     performed after every upgrade domain upgrade completion for all completed
     upgrade domains to make sure the state of the upgrade domains is within
     tolerated limits. The default value is 15%.
    :type max_percent_upgrade_domain_delta_unhealthy_nodes: int
    """

    _validation = {
        'max_percent_delta_unhealthy_nodes': {'maximum': 100, 'minimum': 0},
        'max_percent_upgrade_domain_delta_unhealthy_nodes': {'maximum': 100, 'minimum': 0},
    }

    _attribute_map = {
        'max_percent_delta_unhealthy_nodes': {'key': 'MaxPercentDeltaUnhealthyNodes', 'type': 'int'},
        'max_percent_upgrade_domain_delta_unhealthy_nodes': {'key': 'MaxPercentUpgradeDomainDeltaUnhealthyNodes', 'type': 'int'},
    }

    def __init__(self, *, max_percent_delta_unhealthy_nodes: int=None, max_percent_upgrade_domain_delta_unhealthy_nodes: int=None, **kwargs) -> None:
        super(ClusterUpgradeHealthPolicyObject, self).__init__(**kwargs)
        self.max_percent_delta_unhealthy_nodes = max_percent_delta_unhealthy_nodes
        self.max_percent_upgrade_domain_delta_unhealthy_nodes = max_percent_upgrade_domain_delta_unhealthy_nodes
