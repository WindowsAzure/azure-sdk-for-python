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


class CurrentUpgradeDomainProgressInfo(Model):
    """Information about the current in-progress upgrade domain.

    :param domain_name: The name of the upgrade domain
    :type domain_name: str
    :param node_upgrade_progress_list: List of upgrading nodes and their
     statuses
    :type node_upgrade_progress_list:
     list[~azure.servicefabric.models.NodeUpgradeProgressInfo]
    """

    _attribute_map = {
        'domain_name': {'key': 'DomainName', 'type': 'str'},
        'node_upgrade_progress_list': {'key': 'NodeUpgradeProgressList', 'type': '[NodeUpgradeProgressInfo]'},
    }

    def __init__(self, **kwargs):
        super(CurrentUpgradeDomainProgressInfo, self).__init__(**kwargs)
        self.domain_name = kwargs.get('domain_name', None)
        self.node_upgrade_progress_list = kwargs.get('node_upgrade_progress_list', None)
