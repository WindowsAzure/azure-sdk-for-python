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


class ActiveDirectory(Model):
    """Active Directory.

    :param active_directory_id: Id of the Active Directory
    :type active_directory_id: str
    :param username: Username of Active Directory domain administrator
    :type username: str
    :param password: Plain text password of Active Directory domain
     administrator
    :type password: str
    :param domain: Name of the Active Directory domain
    :type domain: str
    :param dns: Comma separated list of DNS server IP addresses for the Active
     Directory domain
    :type dns: str
    :param status: Status of the Active Directory
    :type status: str
    :param smb_server_name: NetBIOS name of the SMB server. This name will be
     registered as a computer account in the AD and used to mount volumes
    :type smb_server_name: str
    :param organizational_unit: The Organizational Unit (OU) within the
     Windows Active Directory
    :type organizational_unit: str
    """

    _attribute_map = {
        'active_directory_id': {'key': 'activeDirectoryId', 'type': 'str'},
        'username': {'key': 'username', 'type': 'str'},
        'password': {'key': 'password', 'type': 'str'},
        'domain': {'key': 'domain', 'type': 'str'},
        'dns': {'key': 'dns', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'smb_server_name': {'key': 'smbServerName', 'type': 'str'},
        'organizational_unit': {'key': 'organizationalUnit', 'type': 'str'},
    }

    def __init__(self, *, active_directory_id: str=None, username: str=None, password: str=None, domain: str=None, dns: str=None, status: str=None, smb_server_name: str=None, organizational_unit: str=None, **kwargs) -> None:
        super(ActiveDirectory, self).__init__(**kwargs)
        self.active_directory_id = active_directory_id
        self.username = username
        self.password = password
        self.domain = domain
        self.dns = dns
        self.status = status
        self.smb_server_name = smb_server_name
        self.organizational_unit = organizational_unit
