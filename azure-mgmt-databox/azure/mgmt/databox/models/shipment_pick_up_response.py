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


class ShipmentPickUpResponse(Model):
    """Shipment pick up response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar confirmation_number: Confirmation number for the pick up request.
    :vartype confirmation_number: str
    :ivar ready_by_time: Time by which shipment should be ready for pick up,
     this is in local time of pick up area.
    :vartype ready_by_time: datetime
    """

    _validation = {
        'confirmation_number': {'readonly': True},
        'ready_by_time': {'readonly': True},
    }

    _attribute_map = {
        'confirmation_number': {'key': 'confirmationNumber', 'type': 'str'},
        'ready_by_time': {'key': 'readyByTime', 'type': 'iso-8601'},
    }

    def __init__(self, **kwargs):
        super(ShipmentPickUpResponse, self).__init__(**kwargs)
        self.confirmation_number = None
        self.ready_by_time = None
