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


class ManagedClusterPoolUpgradeProfileUpgradesItem(Model):
    """ManagedClusterPoolUpgradeProfileUpgradesItem.

    :param kubernetes_version: Kubernetes version (major, minor, patch).
    :type kubernetes_version: str
    :param is_preview: Whether Kubernetes version is currently in preview.
    :type is_preview: bool
    """

    _attribute_map = {
        'kubernetes_version': {'key': 'kubernetesVersion', 'type': 'str'},
        'is_preview': {'key': 'isPreview', 'type': 'bool'},
    }

    def __init__(self, *, kubernetes_version: str=None, is_preview: bool=None, **kwargs) -> None:
        super(ManagedClusterPoolUpgradeProfileUpgradesItem, self).__init__(**kwargs)
        self.kubernetes_version = kubernetes_version
        self.is_preview = is_preview
