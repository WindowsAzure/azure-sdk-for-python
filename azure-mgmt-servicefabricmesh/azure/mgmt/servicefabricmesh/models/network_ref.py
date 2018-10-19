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


class NetworkRef(Model):
    """Describes a network reference in a service.

    :param name: Name of the network
    :type name: str
    :param endpoint_refs: A list of endpoints that are exposed on this
     network.
    :type endpoint_refs:
     list[~azure.mgmt.servicefabricmesh.models.EndpointRef]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'endpoint_refs': {'key': 'endpointRefs', 'type': '[EndpointRef]'},
    }

    def __init__(self, **kwargs):
        super(NetworkRef, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.endpoint_refs = kwargs.get('endpoint_refs', None)
