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


class ValidateProductTransferEligibilityError(Model):
    """Error details of the product transfer eligibility validation.

    :param code: Error code for the product transfer validation. Possible
     values include: 'InvalidSource', 'ProductNotActive',
     'InsufficienctPermissionOnSource', 'InsufficienctPermissionOnDestination',
     'DestinationBillingProfilePastDue', 'ProductTypeNotSupported',
     'CrossBillingAccountNotAllowed', 'NotAvailableForDestinationMarket',
     'OneTimePurchaseProductTransferNotAllowed'
    :type code: str or
     ~azure.mgmt.billing.models.ProductTransferValidationErrorCode
    :param message: The error message.
    :type message: str
    :param details: Detailed error message explaining the error.
    :type details: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': 'str'},
    }

    def __init__(self, *, code=None, message: str=None, details: str=None, **kwargs) -> None:
        super(ValidateProductTransferEligibilityError, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.details = details
