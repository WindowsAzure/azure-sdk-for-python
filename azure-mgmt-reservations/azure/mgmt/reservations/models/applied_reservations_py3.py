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


class AppliedReservations(Model):
    """AppliedReservations.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Identifier of the applied reservations
    :vartype id: str
    :ivar name: Name of resource
    :vartype name: str
    :ivar type: Type of resource. "Microsoft.Capacity/AppliedReservations"
    :vartype type: str
    :param reservation_order_ids:
    :type reservation_order_ids:
     ~azure.mgmt.reservations.models.AppliedReservationList
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'reservation_order_ids': {'key': 'properties.reservationOrderIds', 'type': 'AppliedReservationList'},
    }

    def __init__(self, *, reservation_order_ids=None, **kwargs) -> None:
        super(AppliedReservations, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.reservation_order_ids = reservation_order_ids
