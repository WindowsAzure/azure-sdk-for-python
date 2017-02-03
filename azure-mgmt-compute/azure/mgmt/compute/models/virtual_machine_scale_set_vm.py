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


class VirtualMachineScaleSetVM(Resource):
    """Describes a virtual machine scale set virtual machine.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict
    :ivar instance_id: The virtual machine instance ID.
    :vartype instance_id: str
    :ivar sku: The virtual machine SKU.
    :vartype sku: :class:`Sku <azure.mgmt.compute.models.Sku>`
    :ivar latest_model_applied: Specifies whether the latest model has been
     applied to the virtual machine.
    :vartype latest_model_applied: bool
    :ivar vm_id: Azure VM unique ID.
    :vartype vm_id: str
    :ivar instance_view: The virtual machine instance view.
    :vartype instance_view: :class:`VirtualMachineInstanceView
     <azure.mgmt.compute.models.VirtualMachineInstanceView>`
    :param hardware_profile: The hardware profile.
    :type hardware_profile: :class:`HardwareProfile
     <azure.mgmt.compute.models.HardwareProfile>`
    :param storage_profile: The storage profile.
    :type storage_profile: :class:`StorageProfile
     <azure.mgmt.compute.models.StorageProfile>`
    :param os_profile: The OS profile.
    :type os_profile: :class:`OSProfile <azure.mgmt.compute.models.OSProfile>`
    :param network_profile: The network profile.
    :type network_profile: :class:`NetworkProfile
     <azure.mgmt.compute.models.NetworkProfile>`
    :param diagnostics_profile: The diagnostics profile.
    :type diagnostics_profile: :class:`DiagnosticsProfile
     <azure.mgmt.compute.models.DiagnosticsProfile>`
    :param availability_set: The reference Id of the availability set to which
     this virtual machine belongs.
    :type availability_set: :class:`SubResource
     <azure.mgmt.compute.models.SubResource>`
    :ivar provisioning_state: The provisioning state, which only appears in
     the response.
    :vartype provisioning_state: str
    :param license_type: The license type, which is for bring your own license
     scenario.
    :type license_type: str
    :param plan: The purchase plan when deploying virtual machine from VM
     Marketplace images.
    :type plan: :class:`Plan <azure.mgmt.compute.models.Plan>`
    :ivar resources: The virtual machine child extension resources.
    :vartype resources: list of :class:`VirtualMachineExtension
     <azure.mgmt.compute.models.VirtualMachineExtension>`
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'instance_id': {'readonly': True},
        'sku': {'readonly': True},
        'latest_model_applied': {'readonly': True},
        'vm_id': {'readonly': True},
        'instance_view': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'resources': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'instance_id': {'key': 'instanceId', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'latest_model_applied': {'key': 'properties.latestModelApplied', 'type': 'bool'},
        'vm_id': {'key': 'properties.vmId', 'type': 'str'},
        'instance_view': {'key': 'properties.instanceView', 'type': 'VirtualMachineInstanceView'},
        'hardware_profile': {'key': 'properties.hardwareProfile', 'type': 'HardwareProfile'},
        'storage_profile': {'key': 'properties.storageProfile', 'type': 'StorageProfile'},
        'os_profile': {'key': 'properties.osProfile', 'type': 'OSProfile'},
        'network_profile': {'key': 'properties.networkProfile', 'type': 'NetworkProfile'},
        'diagnostics_profile': {'key': 'properties.diagnosticsProfile', 'type': 'DiagnosticsProfile'},
        'availability_set': {'key': 'properties.availabilitySet', 'type': 'SubResource'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'license_type': {'key': 'properties.licenseType', 'type': 'str'},
        'plan': {'key': 'plan', 'type': 'Plan'},
        'resources': {'key': 'resources', 'type': '[VirtualMachineExtension]'},
    }

    def __init__(self, location, tags=None, hardware_profile=None, storage_profile=None, os_profile=None, network_profile=None, diagnostics_profile=None, availability_set=None, license_type=None, plan=None):
        super(VirtualMachineScaleSetVM, self).__init__(location=location, tags=tags)
        self.instance_id = None
        self.sku = None
        self.latest_model_applied = None
        self.vm_id = None
        self.instance_view = None
        self.hardware_profile = hardware_profile
        self.storage_profile = storage_profile
        self.os_profile = os_profile
        self.network_profile = network_profile
        self.diagnostics_profile = diagnostics_profile
        self.availability_set = availability_set
        self.provisioning_state = None
        self.license_type = license_type
        self.plan = plan
        self.resources = None
