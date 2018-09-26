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

from .compute_secrets_py3 import ComputeSecrets


class VirtualMachineSecrets(ComputeSecrets):
    """Secrets related to a Machine Learning compute based on AKS.

    All required parameters must be populated in order to send to Azure.

    :param compute_type: Required. Constant filled by server.
    :type compute_type: str
    :param administrator_account: Admin creadentials for virtual machine.
    :type administrator_account:
     ~azure.mgmt.machinelearningservices.models.VirtualMachineSshCredentials
    """

    _validation = {
        'compute_type': {'required': True},
    }

    _attribute_map = {
        'compute_type': {'key': 'computeType', 'type': 'str'},
        'administrator_account': {'key': 'administratorAccount', 'type': 'VirtualMachineSshCredentials'},
    }

    def __init__(self, *, administrator_account=None, **kwargs) -> None:
        super(VirtualMachineSecrets, self).__init__(**kwargs)
        self.administrator_account = administrator_account
        self.compute_type = 'VirtualMachine'
