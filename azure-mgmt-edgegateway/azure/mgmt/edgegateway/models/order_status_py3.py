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


class OrderStatus(Model):
    """Represents a single status change.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param status: Required. Status of the order as per the allowed status
     types. Possible values include: 'Untracked', 'AwaitingFulfilment',
     'AwaitingPreparation', 'AwaitingShipment', 'Shipped', 'Arriving',
     'Delivered', 'ReplacementRequested', 'LostDevice', 'Declined',
     'ReturnInitiated', 'AwaitingReturnShipment', 'ShippedBack',
     'CollectedAtMicrosoft'
    :type status: str or ~azure.mgmt.edgegateway.models.OrderState
    :ivar update_date_time: Time of status update.
    :vartype update_date_time: datetime
    :param comments: Comments related to this status change.
    :type comments: str
    """

    _validation = {
        'status': {'required': True},
        'update_date_time': {'readonly': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'update_date_time': {'key': 'updateDateTime', 'type': 'iso-8601'},
        'comments': {'key': 'comments', 'type': 'str'},
    }

    def __init__(self, *, status, comments: str=None, **kwargs) -> None:
        super(OrderStatus, self).__init__(**kwargs)
        self.status = status
        self.update_date_time = None
        self.comments = comments
