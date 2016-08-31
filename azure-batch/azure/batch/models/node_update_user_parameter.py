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


class NodeUpdateUserParameter(Model):
    """Parameters for a ComputeNodeOperations.UpdateUser request.

    :param password: The password of the account.
    :type password: str
    :param expiry_time: The time at which the account should expire. If
     omitted, the default is 1 day from the current time.
    :type expiry_time: datetime
    :param ssh_public_key: The SSH public key that can be used for remote
     login to the compute node.
    :type ssh_public_key: str
    """ 

    _attribute_map = {
        'password': {'key': 'password', 'type': 'str'},
        'expiry_time': {'key': 'expiryTime', 'type': 'iso-8601'},
        'ssh_public_key': {'key': 'sshPublicKey', 'type': 'str'},
    }

    def __init__(self, password=None, expiry_time=None, ssh_public_key=None):
        self.password = password
        self.expiry_time = expiry_time
        self.ssh_public_key = ssh_public_key
