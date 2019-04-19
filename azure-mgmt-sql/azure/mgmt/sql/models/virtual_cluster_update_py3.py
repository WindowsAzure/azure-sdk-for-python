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


class VirtualClusterUpdate(Model):
    """An update request for an Azure SQL Database virtual cluster.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar subnet_id: Subnet resource ID for the virtual cluster.
    :vartype subnet_id: str
    :param family: If the service has different generations of hardware, for
     the same SKU, then that can be captured here.
    :type family: str
    :ivar child_resources: List of resources in this virtual cluster.
    :vartype child_resources: list[str]
    :param tags: Resource tags.
    :type tags: dict[str, str]
    """

    _validation = {
        'subnet_id': {'readonly': True},
        'child_resources': {'readonly': True},
    }

    _attribute_map = {
        'subnet_id': {'key': 'properties.subnetId', 'type': 'str'},
        'family': {'key': 'properties.family', 'type': 'str'},
        'child_resources': {'key': 'properties.childResources', 'type': '[str]'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, family: str=None, tags=None, **kwargs) -> None:
        super(VirtualClusterUpdate, self).__init__(**kwargs)
        self.subnet_id = None
        self.family = family
        self.child_resources = None
        self.tags = tags
