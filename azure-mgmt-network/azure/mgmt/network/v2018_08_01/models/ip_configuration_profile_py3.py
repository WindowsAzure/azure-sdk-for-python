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


class IPConfigurationProfile(SubResource):
    """IP configuration profile child resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param subnet: The reference of the subnet resource to create a container
     network interface ip configuration.
    :type subnet: ~azure.mgmt.network.v2018_08_01.models.Subnet
    :ivar provisioning_state: The provisioning state of the resource.
    :vartype provisioning_state: str
    :param name: The name of the resource. This name can be used to access the
     resource.
    :type name: str
    :ivar type: Sub Resource type.
    :vartype type: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'subnet': {'key': 'properties.subnet', 'type': 'Subnet'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, subnet=None, name: str=None, etag: str=None, **kwargs) -> None:
        super(IPConfigurationProfile, self).__init__(id=id, **kwargs)
        self.subnet = subnet
        self.provisioning_state = None
        self.name = name
        self.type = None
        self.etag = etag
