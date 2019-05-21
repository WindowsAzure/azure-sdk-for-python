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


class ReservationOrderResponse(Model):
    """ReservationOrderResponse.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param etag:
    :type etag: int
    :ivar id: Identifier of the reservation
    :vartype id: str
    :ivar name: Name of the reservation
    :vartype name: str
    :param display_name: Friendly name for user to easily identified the
     reservation.
    :type display_name: str
    :param request_date_time: This is the DateTime when the reservation was
     initially requested for purchase.
    :type request_date_time: datetime
    :param created_date_time: This is the DateTime when the reservation was
     created.
    :type created_date_time: datetime
    :param expiry_date: This is the date when the Reservation will expire.
    :type expiry_date: date
    :param original_quantity:
    :type original_quantity: int
    :param term: Possible values include: 'P1Y', 'P3Y'
    :type term: str or ~azure.mgmt.reservations.models.ReservationTerm
    :param provisioning_state: Current state of the reservation.
    :type provisioning_state: str
    :param reservations:
    :type reservations:
     list[~azure.mgmt.reservations.models.ReservationResponse]
    :ivar type: Type of resource. "Microsoft.Capacity/reservations"
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'etag': {'key': 'etag', 'type': 'int'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'request_date_time': {'key': 'properties.requestDateTime', 'type': 'iso-8601'},
        'created_date_time': {'key': 'properties.createdDateTime', 'type': 'iso-8601'},
        'expiry_date': {'key': 'properties.expiryDate', 'type': 'date'},
        'original_quantity': {'key': 'properties.originalQuantity', 'type': 'int'},
        'term': {'key': 'properties.term', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'reservations': {'key': 'properties.reservations', 'type': '[ReservationResponse]'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, etag: int=None, display_name: str=None, request_date_time=None, created_date_time=None, expiry_date=None, original_quantity: int=None, term=None, provisioning_state: str=None, reservations=None, **kwargs) -> None:
        super(ReservationOrderResponse, self).__init__(**kwargs)
        self.etag = etag
        self.id = None
        self.name = None
        self.display_name = display_name
        self.request_date_time = request_date_time
        self.created_date_time = created_date_time
        self.expiry_date = expiry_date
        self.original_quantity = original_quantity
        self.term = term
        self.provisioning_state = provisioning_state
        self.reservations = reservations
        self.type = None
