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
     ~azure.mgmt.containerservice.v2019_02_01_preview.models.OSType
    :param upgrades: List of orchestrator types and versions available for
     upgrade.
    :type upgrades: list[str]
    """

    _validation = {
        'kubernetes_version': {'required': True},
        'os_type': {'required': True},
    }

    _attribute_map = {
        'kubernetes_version': {'key': 'kubernetesVersion', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'os_type': {'key': 'osType', 'type': 'str'},
        'upgrades': {'key': 'upgrades', 'type': '[str]'},
    }

    def __init__(self, *, kubernetes_version: str, name: str=None, os_type="Linux", upgrades=None, **kwargs) -> None:
        super(ManagedClusterPoolUpgradeProfile, self).__init__(**kwargs)
        self.kubernetes_version = kubernetes_version
        self.name = name
        self.os_type = os_type
        self.upgrades = upgrades
