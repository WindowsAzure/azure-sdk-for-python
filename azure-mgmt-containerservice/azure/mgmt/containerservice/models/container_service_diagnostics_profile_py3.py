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


class ContainerServiceDiagnosticsProfile(Model):
    """Profile for diagnostics on the container service cluster.

    All required parameters must be populated in order to send to Azure.

    :param vm_diagnostics: Required. Profile for diagnostics on the container
     service VMs.
    :type vm_diagnostics:
     ~azure.mgmt.containerservice.models.ContainerServiceVMDiagnostics
    """

    _validation = {
        'vm_diagnostics': {'required': True},
    }

    _attribute_map = {
        'vm_diagnostics': {'key': 'vmDiagnostics', 'type': 'ContainerServiceVMDiagnostics'},
    }

    def __init__(self, *, vm_diagnostics, **kwargs) -> None:
        super(ContainerServiceDiagnosticsProfile, self).__init__(**kwargs)
        self.vm_diagnostics = vm_diagnostics
