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


class VmSizeCompatibilityFilterV2(Model):
    """This class represent a single filter object that defines a multidimensional
    set. The dimensions of this set are Regions, ClusterFlavors, NodeTypes and
    ClusterVersionsThe dimensions of this set are Regions, ClusterFlavors,
    NodeTypes and ClusterVersions. The constraint should be defined based on
    the following: FilterMode (Exclude vs Include), VMSizes (the vm sizes in
    affect of exlucsion/inclusion) and the ordering of the Filters. Later
    filters override previous settings if conflicted.

    :param filter_mode: The filtering mode. Effectively this can enabling or
     disabling the VM sizes in a particular set.
    :type filter_mode: str
    :param regions: The list of regions under the effect of the filter.
    :type regions: list[str]
    :param cluster_flavors: The list of cluster flavors under the effect of
     the filter.
    :type cluster_flavors: list[str]
    :param node_types: The list of node types affected by the filter.
    :type node_types: list[str]
    :param cluster_versions: The list of cluster versions affected in
     Major.Minor format.
    :type cluster_versions: list[str]
    :param os_type: The OSType affected, Windows or Linux.
    :type os_type: list[str]
    :param vm_sizes: The list of virtual machine sizes to include or exclude.
    :type vm_sizes: list[str]
    """

    _attribute_map = {
        'filter_mode': {'key': 'filterMode', 'type': 'str'},
        'regions': {'key': 'regions', 'type': '[str]'},
        'cluster_flavors': {'key': 'clusterFlavors', 'type': '[str]'},
        'node_types': {'key': 'nodeTypes', 'type': '[str]'},
        'cluster_versions': {'key': 'clusterVersions', 'type': '[str]'},
        'os_type': {'key': 'osType', 'type': '[str]'},
        'vm_sizes': {'key': 'vmSizes', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(VmSizeCompatibilityFilterV2, self).__init__(**kwargs)
        self.filter_mode = kwargs.get('filter_mode', None)
        self.regions = kwargs.get('regions', None)
        self.cluster_flavors = kwargs.get('cluster_flavors', None)
        self.node_types = kwargs.get('node_types', None)
        self.cluster_versions = kwargs.get('cluster_versions', None)
        self.os_type = kwargs.get('os_type', None)
        self.vm_sizes = kwargs.get('vm_sizes', None)
