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


class VirtualMachineInstanceView(Model):
    """The instance view of a virtual machine.

    :param platform_update_domain: Specifies the update domain of the virtual
     machine.
    :type platform_update_domain: int
    :param platform_fault_domain: Specifies the fault domain of the virtual
     machine.
    :type platform_fault_domain: int
    :param rdp_thumb_print: The Remote desktop certificate thumbprint.
    :type rdp_thumb_print: str
    :param vm_agent: The VM Agent running on the virtual machine.
    :type vm_agent:
     ~azure.mgmt.compute.v2016_03_30.models.VirtualMachineAgentInstanceView
    :param disks: The virtual machine disk information.
    :type disks: list[~azure.mgmt.compute.v2016_03_30.models.DiskInstanceView]
    :param extensions: The extensions information.
    :type extensions:
     list[~azure.mgmt.compute.v2016_03_30.models.VirtualMachineExtensionInstanceView]
    :param boot_diagnostics: Boot Diagnostics is a debugging feature which
     allows you to view Console Output and Screenshot to diagnose VM status.
     <br><br> For Linux Virtual Machines, you can easily view the output of
     your console log. <br><br> For both Windows and Linux virtual machines,
     Azure also enables you to see a screenshot of the VM from the hypervisor.
    :type boot_diagnostics:
     ~azure.mgmt.compute.v2016_03_30.models.BootDiagnosticsInstanceView
    :param statuses: The resource status information.
    :type statuses:
     list[~azure.mgmt.compute.v2016_03_30.models.InstanceViewStatus]
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

    def __init__(self, **kwargs):
        super(VirtualMachineInstanceView, self).__init__(**kwargs)
        self.platform_update_domain = kwargs.get('platform_update_domain', None)
        self.platform_fault_domain = kwargs.get('platform_fault_domain', None)
        self.rdp_thumb_print = kwargs.get('rdp_thumb_print', None)
        self.vm_agent = kwargs.get('vm_agent', None)
        self.disks = kwargs.get('disks', None)
        self.extensions = kwargs.get('extensions', None)
        self.boot_diagnostics = kwargs.get('boot_diagnostics', None)
        self.statuses = kwargs.get('statuses', None)
