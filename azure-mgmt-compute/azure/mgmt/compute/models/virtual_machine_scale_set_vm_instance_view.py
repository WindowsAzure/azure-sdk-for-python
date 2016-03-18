# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class VirtualMachineScaleSetVMInstanceView(Model):
    """
    The instance view of a virtual machine scale set VM.

    :param platform_update_domain: Gets or sets the Update Domain count.
    :type platform_update_domain: int
    :param platform_fault_domain: Gets or sets the Fault Domain count.
    :type platform_fault_domain: int
    :param rdp_thumb_print: Gets or sets the Remote desktop certificate
     thumbprint.
    :type rdp_thumb_print: str
    :param vm_agent: Gets or sets the VM Agent running on the virtual machine.
    :type vm_agent: :class:`VirtualMachineAgentInstanceView
     <azure.mgmt.compute.models.VirtualMachineAgentInstanceView>`
    :param disks: Gets or sets the disks information.
    :type disks: list of :class:`DiskInstanceView
     <azure.mgmt.compute.models.DiskInstanceView>`
    :param extensions: Gets or sets the extensions information.
    :type extensions: list of :class:`VirtualMachineExtensionInstanceView
     <azure.mgmt.compute.models.VirtualMachineExtensionInstanceView>`
    :param boot_diagnostics: Gets or sets the boot diagnostics.
    :type boot_diagnostics: :class:`BootDiagnosticsInstanceView
     <azure.mgmt.compute.models.BootDiagnosticsInstanceView>`
    :param statuses: Gets or sets the resource status information.
    :type statuses: list of :class:`InstanceViewStatus
     <azure.mgmt.compute.models.InstanceViewStatus>`
    """ 

    _attribute_map = {
        'platform_update_domain': {'key': 'platformUpdateDomain', 'type': 'int'},
        'platform_fault_domain': {'key': 'platformFaultDomain', 'type': 'int'},
        'rdp_thumb_print': {'key': 'rdpThumbPrint', 'type': 'str'},
        'vm_agent': {'key': 'vmAgent', 'type': 'VirtualMachineAgentInstanceView'},
        'disks': {'key': 'disks', 'type': '[DiskInstanceView]'},
        'extensions': {'key': 'extensions', 'type': '[VirtualMachineExtensionInstanceView]'},
        'boot_diagnostics': {'key': 'bootDiagnostics', 'type': 'BootDiagnosticsInstanceView'},
        'statuses': {'key': 'statuses', 'type': '[InstanceViewStatus]'},
    }

    def __init__(self, platform_update_domain=None, platform_fault_domain=None, rdp_thumb_print=None, vm_agent=None, disks=None, extensions=None, boot_diagnostics=None, statuses=None, **kwargs):
        self.platform_update_domain = platform_update_domain
        self.platform_fault_domain = platform_fault_domain
        self.rdp_thumb_print = rdp_thumb_print
        self.vm_agent = vm_agent
        self.disks = disks
        self.extensions = extensions
        self.boot_diagnostics = boot_diagnostics
        self.statuses = statuses
