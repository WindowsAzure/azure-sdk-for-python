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


class InitiateTransferRequest(Model):
    """Request parameters to initiate transfer.

    :param recipient_email_id: Email Id of recipient for transfer.
    :type recipient_email_id: str
    :param reseller_id: Optional reseller Id for transfer.
    :type reseller_id: str
    """

    _attribute_map = {
        'recipient_email_id': {'key': 'properties.recipientEmailId', 'type': 'str'},
        'reseller_id': {'key': 'properties.resellerId', 'type': 'str'},
    }

    def __init__(self, *, recipient_email_id: str=None, reseller_id: str=None, **kwargs) -> None:
        super(InitiateTransferRequest, self).__init__(**kwargs)
        self.recipient_email_id = recipient_email_id
        self.reseller_id = reseller_id
