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


class SshPublicKey(Model):
    """Contains information about SSH certificate public key and the path on the
    Linux VM where the public key is placed.

    :param path: Specifies the full path on the created VM where ssh public
     key is stored. If the file already exists, the specified key is appended
     to the file. Example: /home/user/.ssh/authorized_keys
    :type path: str
    :param key_data: SSH public key certificate used to authenticate with the
     VM through ssh. The key needs to be at least 2048-bit and in ssh-rsa
     format. <br><br> For creating ssh keys, see [Create SSH keys on Linux and
     Mac for Linux VMs in
     Azure](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-linux-mac-create-ssh-keys?toc=%2fazure%2fvirtual-machines%2flinux%2ftoc.json).
    :type key_data: str
    """

    _attribute_map = {
        'path': {'key': 'path', 'type': 'str'},
        'key_data': {'key': 'keyData', 'type': 'str'},
    }

    def __init__(self, *, path: str=None, key_data: str=None, **kwargs) -> None:
        super(SshPublicKey, self).__init__(**kwargs)
        self.path = path
        self.key_data = key_data
