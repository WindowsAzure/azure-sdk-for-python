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


class ClusterCreateProperties(Model):
    """The cluster create parameters.

    :param cluster_version: The version of the cluster.
    :type cluster_version: str
    :param os_type: The type of operating system. Possible values include:
     'Windows', 'Linux'
    :type os_type: str or ~azure.mgmt.hdinsight.models.OSType
    :param tier: The cluster tier. Possible values include: 'Standard',
     'Premium'
    :type tier: str or ~azure.mgmt.hdinsight.models.Tier
    :param cluster_definition: The cluster definition.
    :type cluster_definition: ~azure.mgmt.hdinsight.models.ClusterDefinition
    :param security_profile: The security profile.
    :type security_profile: ~azure.mgmt.hdinsight.models.SecurityProfile
    :param compute_profile: The compute profile.
    :type compute_profile: ~azure.mgmt.hdinsight.models.ComputeProfile
    :param storage_profile: The storage profile.
    :type storage_profile: ~azure.mgmt.hdinsight.models.StorageProfile
    :param disk_encryption_properties: The disk encryption properties.
    :type disk_encryption_properties:
     ~azure.mgmt.hdinsight.models.DiskEncryptionProperties
    """

    _attribute_map = {
        'cluster_version': {'key': 'clusterVersion', 'type': 'str'},
        'os_type': {'key': 'osType', 'type': 'OSType'},
        'tier': {'key': 'tier', 'type': 'Tier'},
        'cluster_definition': {'key': 'clusterDefinition', 'type': 'ClusterDefinition'},
        'security_profile': {'key': 'securityProfile', 'type': 'SecurityProfile'},
        'compute_profile': {'key': 'computeProfile', 'type': 'ComputeProfile'},
        'storage_profile': {'key': 'storageProfile', 'type': 'StorageProfile'},
        'disk_encryption_properties': {'key': 'diskEncryptionProperties', 'type': 'DiskEncryptionProperties'},
    }

    def __init__(self, *, cluster_version: str=None, os_type=None, tier=None, cluster_definition=None, security_profile=None, compute_profile=None, storage_profile=None, disk_encryption_properties=None, **kwargs) -> None:
        super(ClusterCreateProperties, self).__init__(**kwargs)
        self.cluster_version = cluster_version
        self.os_type = os_type
        self.tier = tier
        self.cluster_definition = cluster_definition
        self.security_profile = security_profile
        self.compute_profile = compute_profile
        self.storage_profile = storage_profile
        self.disk_encryption_properties = disk_encryption_properties
