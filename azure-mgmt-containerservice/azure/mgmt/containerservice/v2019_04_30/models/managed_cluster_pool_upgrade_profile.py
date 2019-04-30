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


class ManagedClusterPoolUpgradeProfile(Model):
    """The list of available upgrade versions.

    All required parameters must be populated in order to send to Azure.

    :param kubernetes_version: Required. Kubernetes version (major, minor,
     patch).
    :type kubernetes_version: str
    :param name: Pool name.
    :type name: str
    :param os_type: Required. OsType to be used to specify os type. Choose
     from Linux and Windows. Default to Linux. Possible values include:
     'Linux', 'Windows'. Default value: "Linux" .
    :type os_type: str or
     ~azure.mgmt.containerservice.v2019_04_30.models.OSType
    :param upgrades: List of orchestrator types and versions available for
     upgrade.
    :type upgrades:
     list[~azure.mgmt.containerservice.v2019_04_30.models.ManagedClusterPoolUpgradeProfileUpgradesItem]
    """

    _validation = {
        'kubernetes_version': {'required': True},
        'os_type': {'required': True},
    }

    _attribute_map = {
        'kubernetes_version': {'key': 'kubernetesVersion', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'os_type': {'key': 'osType', 'type': 'str'},
        'upgrades': {'key': 'upgrades', 'type': '[ManagedClusterPoolUpgradeProfileUpgradesItem]'},
    }

    def __init__(self, **kwargs):
        super(ManagedClusterPoolUpgradeProfile, self).__init__(**kwargs)
        self.kubernetes_version = kwargs.get('kubernetes_version', None)
        self.name = kwargs.get('name', None)
        self.os_type = kwargs.get('os_type', "Linux")
        self.upgrades = kwargs.get('upgrades', None)
