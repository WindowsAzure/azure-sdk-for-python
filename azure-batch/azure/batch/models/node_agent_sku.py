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


class NodeAgentSku(Model):
    """A node agent SKU supported by the Batch service.

    The Batch node agent is a program that runs on each node in the pool, and
    provides the command-and-control interface between the node and the Batch
    service. There are different implementations of the node agent, known as
    SKUs, for different operating systems.

    :param id: The ID of the node agent SKU.
    :type id: str
    :param verified_image_references: The list of Azure Marketplace images
     verified to be compatible with this node agent SKU. This collection is not
     exhaustive (the node agent may be compatible with other images).
    :type verified_image_references: list[~azure.batch.models.ImageReference]
    :param os_type: The type of operating system (e.g. Windows or Linux)
     compatible with the node agent SKU. Possible values include: 'linux',
     'windows'
    :type os_type: str or ~azure.batch.models.OSType
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'verified_image_references': {'key': 'verifiedImageReferences', 'type': '[ImageReference]'},
        'os_type': {'key': 'osType', 'type': 'OSType'},
    }

    def __init__(self, **kwargs):
        super(NodeAgentSku, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.verified_image_references = kwargs.get('verified_image_references', None)
        self.os_type = kwargs.get('os_type', None)
