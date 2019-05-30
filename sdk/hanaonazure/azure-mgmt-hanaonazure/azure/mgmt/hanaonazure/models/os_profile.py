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
    """Specifies the operating system settings for the HANA instance.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar computer_name: Specifies the host OS name of the HANA instance.
    :vartype computer_name: str
    :ivar os_type: This property allows you to specify the type of the OS.
    :vartype os_type: str
    :ivar version: Specifies version of operating system.
    :vartype version: str
    :ivar ssh_public_key: Specifies the SSH public key used to access the
     operating system.
    :vartype ssh_public_key: str
    """

    _validation = {
        'computer_name': {'readonly': True},
        'os_type': {'readonly': True},
        'version': {'readonly': True},
        'ssh_public_key': {'readonly': True},
    }

    _attribute_map = {
        'computer_name': {'key': 'computerName', 'type': 'str'},
        'os_type': {'key': 'osType', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'ssh_public_key': {'key': 'sshPublicKey', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OSProfile, self).__init__(**kwargs)
        self.computer_name = None
        self.os_type = None
        self.version = None
        self.ssh_public_key = None
