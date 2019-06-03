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


class VirtualMachineTemplate(Model):
    """Virtual machine template model.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: virtual machine template id (privateCloudId:vsphereId)
    :vartype id: str
    :param location: Azure region
    :type location: str
    :ivar name: {virtualMachineTemplateName}
    :vartype name: str
    :param amount_of_ram: The amount of memory
    :type amount_of_ram: int
    :param controllers: The list of Virtual Disk Controllers
    :type controllers:
     list[~microsoft.vmwarecloudsimple.models.VirtualDiskController]
    :param description: The description of Virtual Machine Template
    :type description: str
    :param disks: The list of Virtual Disks
    :type disks: list[~microsoft.vmwarecloudsimple.models.VirtualDisk]
    :param expose_to_guest_vm: Expose Guest OS or not
    :type expose_to_guest_vm: bool
    :param guest_os: Required. The Guest OS
    :type guest_os: str
    :param guest_os_type: Required. The Guest OS types
    :type guest_os_type: str
    :param nics: The list of Virtual NICs
    :type nics: list[~microsoft.vmwarecloudsimple.models.VirtualNic]
    :param number_of_cores: The number of CPU cores
    :type number_of_cores: int
    :param path: path to folder
    :type path: str
    :param private_cloud_id: Required. The Private Cloud Id
    :type private_cloud_id: str
    :param v_sphere_networks: The list of VSphere networks
    :type v_sphere_networks: list[str]
    :param v_sphere_tags: The tags from VSphere
    :type v_sphere_tags: list[str]
    :ivar vmwaretools: The VMware tools version
    :vartype vmwaretools: str
    :ivar type: {resourceProviderNamespace}/{resourceType}
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'guest_os': {'required': True},
        'guest_os_type': {'required': True},
        'private_cloud_id': {'required': True},
        'vmwaretools': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'amount_of_ram': {'key': 'properties.amountOfRam', 'type': 'int'},
        'controllers': {'key': 'properties.controllers', 'type': '[VirtualDiskController]'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'disks': {'key': 'properties.disks', 'type': '[VirtualDisk]'},
        'expose_to_guest_vm': {'key': 'properties.exposeToGuestVM', 'type': 'bool'},
        'guest_os': {'key': 'properties.guestOS', 'type': 'str'},
        'guest_os_type': {'key': 'properties.guestOSType', 'type': 'str'},
        'nics': {'key': 'properties.nics', 'type': '[VirtualNic]'},
        'number_of_cores': {'key': 'properties.numberOfCores', 'type': 'int'},
        'path': {'key': 'properties.path', 'type': 'str'},
        'private_cloud_id': {'key': 'properties.privateCloudId', 'type': 'str'},
        'v_sphere_networks': {'key': 'properties.vSphereNetworks', 'type': '[str]'},
        'v_sphere_tags': {'key': 'properties.vSphereTags', 'type': '[str]'},
        'vmwaretools': {'key': 'properties.vmwaretools', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, guest_os: str, guest_os_type: str, private_cloud_id: str, location: str=None, amount_of_ram: int=None, controllers=None, description: str=None, disks=None, expose_to_guest_vm: bool=None, nics=None, number_of_cores: int=None, path: str=None, v_sphere_networks=None, v_sphere_tags=None, **kwargs) -> None:
        super(VirtualMachineTemplate, self).__init__(**kwargs)
        self.id = None
        self.location = location
        self.name = None
        self.amount_of_ram = amount_of_ram
        self.controllers = controllers
        self.description = description
        self.disks = disks
        self.expose_to_guest_vm = expose_to_guest_vm
        self.guest_os = guest_os
        self.guest_os_type = guest_os_type
        self.nics = nics
        self.number_of_cores = number_of_cores
        self.path = path
        self.private_cloud_id = private_cloud_id
        self.v_sphere_networks = v_sphere_networks
        self.v_sphere_tags = v_sphere_tags
        self.vmwaretools = None
        self.type = None
