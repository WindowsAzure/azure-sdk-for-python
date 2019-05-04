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


class LinuxConfiguration(Model):
    """Specifies the Linux operating system settings on the virtual machine.
    <br><br>For a list of supported Linux distributions, see [Linux on
    Azure-Endorsed
    Distributions](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-linux-endorsed-distros?toc=%2fazure%2fvirtual-machines%2flinux%2ftoc.json)
    <br><br> For running non-endorsed distributions, see [Information for
    Non-Endorsed
    Distributions](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-linux-create-upload-generic?toc=%2fazure%2fvirtual-machines%2flinux%2ftoc.json).

    :param disable_password_authentication: Specifies whether password
     authentication should be disabled.
    :type disable_password_authentication: bool
    :param ssh: Specifies the ssh key configuration for a Linux OS.
    :type ssh: ~azure.mgmt.compute.v2019_03_01.models.SshConfiguration
    :param provision_vm_agent: Indicates whether virtual machine agent should
     be provisioned on the virtual machine. <br><br> When this property is not
     specified in the request body, default behavior is to set it to true.
     This will ensure that VM Agent is installed on the VM so that extensions
     can be added to the VM later.
    :type provision_vm_agent: bool
    """

    _attribute_map = {
        'disable_password_authentication': {'key': 'disablePasswordAuthentication', 'type': 'bool'},
        'ssh': {'key': 'ssh', 'type': 'SshConfiguration'},
        'provision_vm_agent': {'key': 'provisionVMAgent', 'type': 'bool'},
    }

    def __init__(self, *, disable_password_authentication: bool=None, ssh=None, provision_vm_agent: bool=None, **kwargs) -> None:
        super(LinuxConfiguration, self).__init__(**kwargs)
        self.disable_password_authentication = disable_password_authentication
        self.ssh = ssh
        self.provision_vm_agent = provision_vm_agent
