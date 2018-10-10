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


class BackendProperties(Model):
    """Properties specific to the Backend Type.

    :param service_fabric_cluster: Backend Service Fabric Cluster Properties
    :type service_fabric_cluster:
     ~azure.mgmt.apimanagement.models.BackendServiceFabricClusterProperties
    """

    _attribute_map = {
        'service_fabric_cluster': {'key': 'serviceFabricCluster', 'type': 'BackendServiceFabricClusterProperties'},
    }

    def __init__(self, **kwargs):
        super(BackendProperties, self).__init__(**kwargs)
        self.service_fabric_cluster = kwargs.get('service_fabric_cluster', None)
