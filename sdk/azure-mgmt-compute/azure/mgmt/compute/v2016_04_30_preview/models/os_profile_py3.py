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


class OSProfile(Model):
    """Specifies the operating system settings for the virtual machine.

    :param computer_name: Specifies the host OS name of the virtual machine.
     <br><br> This name cannot be updated after the VM is created. <br><br>
     **Max-length (Windows):** 15 characters <br><br> **Max-length (Linux):**
     64 characters. <br><br> For naming conventions and restrictions see [Azure
     infrastructure services implementation
     guidelines](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-linux-infrastructure-subscription-accounts-guidelines?toc=%2fazure%2fvirtual-machines%2flinux%2ftoc.json#1-naming-conventions).
    :type computer_name: str
    :param admin_username: Specifies the name of the administrator account.
     <br><br> **Windows-only restriction:** Cannot end in "." <br><br>
     **Disallowed values:** "administrator", "admin", "user", "user1", "test",
     "user2", "test1", "user3", "admin1", "1", "123", "a", "actuser", "adm",
     "admin2", "aspnet", "backup", "console", "david", "guest", "john",
     "owner", "root", "server", "sql", "support", "support_388945a0", "sys",
     "test2", "test3", "user4", "user5". <br><br> **Minimum-length (Linux):** 1
     character <br><br> **Max-length (Linux):** 64 characters <br><br>
     **Max-length (Windows):** 20 characters  <br><br><li> For root access to
     the Linux VM, see [Using root privileges on Linux virtual machines in
     Azure](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-linux-use-root-privileges?toc=%2fazure%2fvirtual-machines%2flinux%2ftoc.json)<br><li>
     For a list of built-in system users on Linux that should not be used in
     this field, see [Selecting User Names for Linux on
     Azure](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-linux-usernames?toc=%2fazure%2fvirtual-machines%2flinux%2ftoc.json)
    :type admin_username: str
    :param admin_password: Specifies the password of the administrator
     account. <br><br> **Minimum-length (Windows):** 8 characters <br><br>
     **Minimum-length (Linux):** 6 characters <br><br> **Max-length
     (Windows):** 123 characters <br><br> **Max-length (Linux):** 72 characters
     <br><br> **Complexity requirements:** 3 out of 4 conditions below need to
     be fulfilled <br> Has lower characters <br>Has upper characters <br> Has a
     digit <br> Has a special character (Regex match [\\W_]) <br><br>
     **Disallowed values:** "abc@123", "P@$$w0rd", "P@ssw0rd", "P@ssword123",
     "Pa$$word", "pass@word1", "Password!", "Password1", "Password22",
     "iloveyou!" <br><br> For resetting the password, see [How to reset the
     Remote Desktop service or its login password in a Windows
     VM](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-windows-reset-rdp?toc=%2fazure%2fvirtual-machines%2fwindows%2ftoc.json)
     <br><br> For resetting root password, see [Manage users, SSH, and check or
     repair disks on Azure Linux VMs using the VMAccess
     Extension](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-linux-using-vmaccess-extension?toc=%2fazure%2fvirtual-machines%2flinux%2ftoc.json#reset-root-password)
    :type admin_password: str
    :param custom_data: Specifies a base-64 encoded string of custom data. The
     base-64 encoded string is decoded to a binary array that is saved as a
     file on the Virtual Machine. The maximum length of the binary array is
     65535 bytes. <br><br> For using cloud-init for your VM, see [Using
     cloud-init to customize a Linux VM during
     creation](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-linux-using-cloud-init?toc=%2fazure%2fvirtual-machines%2flinux%2ftoc.json)
    :type custom_data: str
    :param windows_configuration: Specifies Windows operating system settings
     on the virtual machine.
    :type windows_configuration:
     ~azure.mgmt.compute.v2016_04_30_preview.models.WindowsConfiguration
    :param linux_configuration: Specifies the Linux operating system settings
     on the virtual machine. <br><br>For a list of supported Linux
     distributions, see [Linux on Azure-Endorsed
     Distributions](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-linux-endorsed-distros?toc=%2fazure%2fvirtual-machines%2flinux%2ftoc.json)
     <br><br> For running non-endorsed distributions, see [Information for
     Non-Endorsed
     Distributions](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-linux-create-upload-generic?toc=%2fazure%2fvirtual-machines%2flinux%2ftoc.json).
    :type linux_configuration:
     ~azure.mgmt.compute.v2016_04_30_preview.models.LinuxConfiguration
    :param secrets: Specifies set of certificates that should be installed
     onto the virtual machine.
    :type secrets:
     list[~azure.mgmt.compute.v2016_04_30_preview.models.VaultSecretGroup]
    """

    _attribute_map = {
        'computer_name': {'key': 'computerName', 'type': 'str'},
        'admin_username': {'key': 'adminUsername', 'type': 'str'},
        'admin_password': {'key': 'adminPassword', 'type': 'str'},
        'custom_data': {'key': 'customData', 'type': 'str'},
        'windows_configuration': {'key': 'windowsConfiguration', 'type': 'WindowsConfiguration'},
        'linux_configuration': {'key': 'linuxConfiguration', 'type': 'LinuxConfiguration'},
        'secrets': {'key': 'secrets', 'type': '[VaultSecretGroup]'},
    }

    def __init__(self, *, computer_name: str=None, admin_username: str=None, admin_password: str=None, custom_data: str=None, windows_configuration=None, linux_configuration=None, secrets=None, **kwargs) -> None:
        super(OSProfile, self).__init__(**kwargs)
        self.computer_name = computer_name
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.custom_data = custom_data
        self.windows_configuration = windows_configuration
        self.linux_configuration = linux_configuration
        self.secrets = secrets
