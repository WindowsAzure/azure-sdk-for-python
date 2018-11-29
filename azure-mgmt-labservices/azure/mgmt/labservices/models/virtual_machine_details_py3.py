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


class VirtualMachineDetails(Model):
    """Details of the backing virtual machine.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provisioning_state: Provisioning state of the Dtl VM
    :vartype provisioning_state: str
    :ivar rdp_authority: Connection information for Windows
    :vartype rdp_authority: str
    :ivar ssh_authority: Connection information for Linux
    :vartype ssh_authority: str
    :ivar private_ip_address: PrivateIp address of the compute VM
    :vartype private_ip_address: str
    :ivar user_name: Compute VM login user name
    :vartype user_name: str
    :ivar last_known_power_state: Last known compute power state captured in
     DTL
    :vartype last_known_power_state: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'rdp_authority': {'readonly': True},
        'ssh_authority': {'readonly': True},
        'private_ip_address': {'readonly': True},
        'user_name': {'readonly': True},
        'last_known_power_state': {'readonly': True},
    }

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'rdp_authority': {'key': 'rdpAuthority', 'type': 'str'},
        'ssh_authority': {'key': 'sshAuthority', 'type': 'str'},
        'private_ip_address': {'key': 'privateIpAddress', 'type': 'str'},
        'user_name': {'key': 'userName', 'type': 'str'},
        'last_known_power_state': {'key': 'lastKnownPowerState', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(VirtualMachineDetails, self).__init__(**kwargs)
        self.provisioning_state = None
        self.rdp_authority = None
        self.ssh_authority = None
        self.private_ip_address = None
        self.user_name = None
        self.last_known_power_state = None
