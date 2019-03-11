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
     ~azure.mgmt.containerservice.v2019_02_01_preview.models.ContainerServiceVMDiagnostics
    """

    _validation = {
        'vm_diagnostics': {'required': True},
    }

    _attribute_map = {
        'vm_diagnostics': {'key': 'vmDiagnostics', 'type': 'ContainerServiceVMDiagnostics'},
    }

    def __init__(self, **kwargs):
        super(ContainerServiceDiagnosticsProfile, self).__init__(**kwargs)
        self.vm_diagnostics = kwargs.get('vm_diagnostics', None)
