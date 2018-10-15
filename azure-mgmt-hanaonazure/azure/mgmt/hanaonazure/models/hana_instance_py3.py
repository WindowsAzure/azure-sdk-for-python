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

from .resource_py3 import Resource


class HanaInstance(Resource):
    """HANA instance info on Azure (ARM properties and HANA properties).

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :ivar location: Resource location
    :vartype location: str
    :ivar tags: Resource tags
    :vartype tags: dict[str, str]
    :param hardware_profile: Specifies the hardware settings for the HANA
     instance.
    :type hardware_profile: ~azure.mgmt.hanaonazure.models.HardwareProfile
    :param storage_profile: Specifies the storage settings for the HANA
     instance disks.
    :type storage_profile: ~azure.mgmt.hanaonazure.models.StorageProfile
    :param os_profile: Specifies the operating system settings for the HANA
     instance.
    :type os_profile: ~azure.mgmt.hanaonazure.models.OSProfile
    :param network_profile: Specifies the network settings for the HANA
     instance.
    :type network_profile: ~azure.mgmt.hanaonazure.models.NetworkProfile
    :ivar hana_instance_id: Specifies the HANA instance unique ID.
    :vartype hana_instance_id: str
    :ivar power_state: Resource power state. Possible values include:
     'starting', 'started', 'stopping', 'stopped', 'restarting', 'unknown'
    :vartype power_state: str or
     ~azure.mgmt.hanaonazure.models.HanaInstancePowerStateEnum
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'readonly': True},
        'tags': {'readonly': True},
        'hana_instance_id': {'readonly': True},
        'power_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'hardware_profile': {'key': 'properties.hardwareProfile', 'type': 'HardwareProfile'},
        'storage_profile': {'key': 'properties.storageProfile', 'type': 'StorageProfile'},
        'os_profile': {'key': 'properties.osProfile', 'type': 'OSProfile'},
        'network_profile': {'key': 'properties.networkProfile', 'type': 'NetworkProfile'},
        'hana_instance_id': {'key': 'properties.hanaInstanceId', 'type': 'str'},
        'power_state': {'key': 'properties.powerState', 'type': 'str'},
    }

    def __init__(self, *, hardware_profile=None, storage_profile=None, os_profile=None, network_profile=None, **kwargs) -> None:
        super(HanaInstance, self).__init__(**kwargs)
        self.hardware_profile = hardware_profile
        self.storage_profile = storage_profile
        self.os_profile = os_profile
        self.network_profile = network_profile
        self.hana_instance_id = None
        self.power_state = None
