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


class ResourceRequests(Model):
    """The resource requests.

    All required parameters must be populated in order to send to Azure.

    :param memory_in_gb: Required. The memory request in GB of this container
     instance.
    :type memory_in_gb: float
    :param cpu: Required. The CPU request of this container instance.
    :type cpu: float
    :param gpu: The GPU request of this container instance.
    :type gpu: ~azure.mgmt.containerinstance.models.GpuResource
    """

    _validation = {
        'memory_in_gb': {'required': True},
        'cpu': {'required': True},
    }

    _attribute_map = {
        'memory_in_gb': {'key': 'memoryInGB', 'type': 'float'},
        'cpu': {'key': 'cpu', 'type': 'float'},
        'gpu': {'key': 'gpu', 'type': 'GpuResource'},
    }

    def __init__(self, *, memory_in_gb: float, cpu: float, gpu=None, **kwargs) -> None:
        super(ResourceRequests, self).__init__(**kwargs)
        self.memory_in_gb = memory_in_gb
        self.cpu = cpu
        self.gpu = gpu
