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


class VirtualMachineScaleSetUpdateOSProfile(Model):
    """Describes a virtual machine scale set OS profile.

    :param custom_data: A base-64 encoded string of custom data.
    :type custom_data: str
    :param windows_configuration: The Windows Configuration of the OS profile.
    :type windows_configuration:
     ~azure.mgmt.compute.v2019_03_01.models.WindowsConfiguration
    :param linux_configuration: The Linux Configuration of the OS profile.
    :type linux_configuration:
     ~azure.mgmt.compute.v2019_03_01.models.LinuxConfiguration
    :param secrets: The List of certificates for addition to the VM.
    :type secrets:
     list[~azure.mgmt.compute.v2019_03_01.models.VaultSecretGroup]
    """

    _attribute_map = {
        'custom_data': {'key': 'customData', 'type': 'str'},
        'windows_configuration': {'key': 'windowsConfiguration', 'type': 'WindowsConfiguration'},
        'linux_configuration': {'key': 'linuxConfiguration', 'type': 'LinuxConfiguration'},
        'secrets': {'key': 'secrets', 'type': '[VaultSecretGroup]'},
    }

    def __init__(self, **kwargs):
        super(VirtualMachineScaleSetUpdateOSProfile, self).__init__(**kwargs)
        self.custom_data = kwargs.get('custom_data', None)
        self.windows_configuration = kwargs.get('windows_configuration', None)
        self.linux_configuration = kwargs.get('linux_configuration', None)
        self.secrets = kwargs.get('secrets', None)
