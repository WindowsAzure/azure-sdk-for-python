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

from .feature_support_request import FeatureSupportRequest


class AzureVMResourceFeatureSupportRequest(FeatureSupportRequest):
    """AzureResource(IaaS VM) Specific feature support request.

    :param feature_type: Constant filled by server.
    :type feature_type: str
    :param vm_size: Size of the resource: VM size(A/D series etc) in case of
     IaasVM
    :type vm_size: str
    :param vm_sku: SKUs (Premium/Managed etc) in case of IaasVM
    :type vm_sku: str
    """

    _validation = {
        'feature_type': {'required': True},
    }

    _attribute_map = {
        'feature_type': {'key': 'featureType', 'type': 'str'},
        'vm_size': {'key': 'vmSize', 'type': 'str'},
        'vm_sku': {'key': 'vmSku', 'type': 'str'},
    }

    def __init__(self, vm_size=None, vm_sku=None):
        super(AzureVMResourceFeatureSupportRequest, self).__init__()
        self.vm_size = vm_size
        self.vm_sku = vm_sku
        self.feature_type = 'AzureVMResourceBackup'
