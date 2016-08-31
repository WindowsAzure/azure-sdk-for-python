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

from .resource import Resource


class VirtualMachine(Resource):
    """Describes a Virtual Machine.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    :param plan: the purchase plan when deploying virtual machine from VM
     Marketplace images.
    :type plan: :class:`Plan <azure.mgmt.compute.models.Plan>`
    :param hardware_profile: the hardware profile.
    :type hardware_profile: :class:`HardwareProfile
     <azure.mgmt.compute.models.HardwareProfile>`
    :param storage_profile: the storage profile.
    :type storage_profile: :class:`StorageProfile
     <azure.mgmt.compute.models.StorageProfile>`
    :param os_profile: the OS profile.
    :type os_profile: :class:`OSProfile <azure.mgmt.compute.models.OSProfile>`
    :param network_profile: the network profile.
    :type network_profile: :class:`NetworkProfile
     <azure.mgmt.compute.models.NetworkProfile>`
    :param diagnostics_profile: the diagnostics profile.
    :type diagnostics_profile: :class:`DiagnosticsProfile
     <azure.mgmt.compute.models.DiagnosticsProfile>`
    :param availability_set: the reference Id of the availability set to
     which this virtual machine belongs.
    :type availability_set: :class:`SubResource
     <azure.mgmt.compute.models.SubResource>`
    :ivar provisioning_state: the provisioning state, which only appears in
     the response.
    :vartype provisioning_state: str
    :ivar instance_view: the virtual machine instance view.
    :vartype instance_view: :class:`VirtualMachineInstanceView
     <azure.mgmt.compute.models.VirtualMachineInstanceView>`
    :param license_type: the license type, which is for bring your own
     license scenario.
    :type license_type: str
    :ivar vm_id: the virtual machine unique id.
    :vartype vm_id: str
    :ivar resources: the virtual machine child extension resources.
    :vartype resources: list of :class:`VirtualMachineExtension
     <azure.mgmt.compute.models.VirtualMachineExtension>`
    """ 

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'instance_view': {'readonly': True},
        'vm_id': {'readonly': True},
        'resources': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'plan': {'key': 'plan', 'type': 'Plan'},
        'hardware_profile': {'key': 'properties.hardwareProfile', 'type': 'HardwareProfile'},
        'storage_profile': {'key': 'properties.storageProfile', 'type': 'StorageProfile'},
        'os_profile': {'key': 'properties.osProfile', 'type': 'OSProfile'},
        'network_profile': {'key': 'properties.networkProfile', 'type': 'NetworkProfile'},
        'diagnostics_profile': {'key': 'properties.diagnosticsProfile', 'type': 'DiagnosticsProfile'},
        'availability_set': {'key': 'properties.availabilitySet', 'type': 'SubResource'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'instance_view': {'key': 'properties.instanceView', 'type': 'VirtualMachineInstanceView'},
        'license_type': {'key': 'properties.licenseType', 'type': 'str'},
        'vm_id': {'key': 'properties.vmId', 'type': 'str'},
        'resources': {'key': 'resources', 'type': '[VirtualMachineExtension]'},
    }

    def __init__(self, location, tags=None, plan=None, hardware_profile=None, storage_profile=None, os_profile=None, network_profile=None, diagnostics_profile=None, availability_set=None, license_type=None):
        super(VirtualMachine, self).__init__(location=location, tags=tags)
        self.plan = plan
        self.hardware_profile = hardware_profile
        self.storage_profile = storage_profile
        self.os_profile = os_profile
        self.network_profile = network_profile
        self.diagnostics_profile = diagnostics_profile
        self.availability_set = availability_set
        self.provisioning_state = None
        self.instance_view = None
        self.license_type = license_type
        self.vm_id = None
        self.resources = None
