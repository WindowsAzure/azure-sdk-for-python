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


class ProvisioningError(Model):
    """ProvisioningError.

    :param provisioning_error_code: Error code of the provisioning failure.
     Possible values include: 'BadSourceType', 'BadPIRSource', 'BadISOSource',
     'BadManagedImageSource', 'BadSharedImageVersionSource',
     'BadCustomizerType', 'UnsupportedCustomizerType', 'NoCustomizerScript',
     'BadDistributeType', 'BadSharedImageDistribute', 'ServerError', 'Other'
    :type provisioning_error_code: str or ~azure.mgmt.imagebuilder.models.enum
    :param message: Verbose error message about the provisioning failure
    :type message: str
    """

    _attribute_map = {
        'provisioning_error_code': {'key': 'provisioningErrorCode', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ProvisioningError, self).__init__(**kwargs)
        self.provisioning_error_code = kwargs.get('provisioning_error_code', None)
        self.message = kwargs.get('message', None)
