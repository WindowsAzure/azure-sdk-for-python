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


class AzureVMResourceFeatureSupportResponse(Model):
    """Response for feature support requests for Azure IaasVm.

    :param support_status: Support status of feature. Possible values include:
     'Invalid', 'Supported', 'DefaultOFF', 'DefaultON', 'NotSupported'
    :type support_status: str or
     ~azure.mgmt.recoveryservicesbackup.models.SupportStatus
    """

    _attribute_map = {
        'support_status': {'key': 'supportStatus', 'type': 'str'},
    }

    def __init__(self, support_status=None):
        super(AzureVMResourceFeatureSupportResponse, self).__init__()
        self.support_status = support_status
