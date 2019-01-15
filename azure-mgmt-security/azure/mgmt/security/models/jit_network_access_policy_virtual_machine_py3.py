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


class JitNetworkAccessPolicyVirtualMachine(Model):
    """JitNetworkAccessPolicyVirtualMachine.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Resource ID of the virtual machine that is linked to
     this policy
    :type id: str
    :param ports: Required. Port configurations for the virtual machine
    :type ports: list[~azure.mgmt.security.models.JitNetworkAccessPortRule]
    """

    _validation = {
        'id': {'required': True},
        'ports': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'ports': {'key': 'ports', 'type': '[JitNetworkAccessPortRule]'},
    }

    def __init__(self, *, id: str, ports, **kwargs) -> None:
        super(JitNetworkAccessPolicyVirtualMachine, self).__init__(**kwargs)
        self.id = id
        self.ports = ports
