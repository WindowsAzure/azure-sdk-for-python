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


class ContainerRegistryProperties(Model):
    """Properties of Azure Container Registry.

    :param resource_id: ARM resource ID of the Azure Container Registry used
     to store Docker images for web services in the cluster. If not provided
     one will be created. This cannot be changed once the cluster is created.
    :type resource_id: str
    """

    _attribute_map = {
        'resource_id': {'key': 'resourceId', 'type': 'str'},
    }

    def __init__(self, *, resource_id: str=None, **kwargs) -> None:
        super(ContainerRegistryProperties, self).__init__(**kwargs)
        self.resource_id = resource_id
