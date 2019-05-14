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


class VirtualMachineHealthStatus(Model):
    """The health status of the VM.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar status: The health status information for the VM.
    :vartype status: ~azure.mgmt.compute.v2017_12_01.models.InstanceViewStatus
    """

    _validation = {
        'status': {'readonly': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'InstanceViewStatus'},
    }

    def __init__(self, **kwargs):
        super(VirtualMachineHealthStatus, self).__init__(**kwargs)
        self.status = None
