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

from .sub_resource_py3 import SubResource


class ContainerNetworkInterfaceConfiguration(SubResource):
    """Container network interface configruation child resource.

    :param id: Resource ID.
    :type id: str
    :param properties: Container network interface configuration properties.
    :type properties:
     ~azure.mgmt.network.v2018_08_01.models.ContainerNetworkInterfaceConfigurationPropertiesFormat
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'ContainerNetworkInterfaceConfigurationPropertiesFormat'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, properties=None, etag: str=None, **kwargs) -> None:
        super(ContainerNetworkInterfaceConfiguration, self).__init__(id=id, **kwargs)
        self.properties = properties
        self.etag = etag
