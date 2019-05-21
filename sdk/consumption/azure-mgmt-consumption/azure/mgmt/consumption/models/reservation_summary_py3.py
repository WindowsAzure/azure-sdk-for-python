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

from .resource_py3 import Resource


class ReservationSummary(Resource):
    """reservation summary resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar tags: Resource tags.
    :vartype tags: dict[str, str]
    :ivar reservation_order_id: The reservation order ID is the identifier for
     a reservation purchase. Each reservation order ID represents a single
     purchase transaction. A reservation order contains reservations. The
     reservation order specifies the VM size and region for the reservations.
    :vartype reservation_order_id: str
    :ivar reservation_id: The reservation ID is the identifier of a
     reservation within a reservation order. Each reservation is the grouping
     for applying the benefit scope and also specifies the number of instances
     to which the reservation benefit can be applied to.
    :vartype reservation_id: str
    :ivar sku_name: This is the ARM Sku name. It can be used to join with the
     serviceType field in additional info in usage records.
    :vartype sku_name: str
    :ivar reserved_hours: This is the total hours reserved. E.g. if
     reservation for 1 instance was made on 1 PM, this will be 11 hours for
     that day and 24 hours from subsequent days
    :vartype reserved_hours: decimal.Decimal
    :ivar usage_date: Data corresponding to the utilization record. If the
     grain of data is monthly, it will be first day of month.
    :vartype usage_date: datetime
    :ivar used_hours: Total used hours by the reservation
    :vartype used_hours: decimal.Decimal
    :ivar min_utilization_percentage: This is the minimum hourly utilization
     in the usage time (day or month). E.g. if usage record corresponds to
     12/10/2017 and on that for hour 4 and 5, utilization was 10%, this field
     will return 10% for that day
    :vartype min_utilization_percentage: decimal.Decimal
    :ivar avg_utilization_percentage: This is average utilization for the
     entire time range. (day or month depending on the grain)
    :vartype avg_utilization_percentage: decimal.Decimal
    :ivar max_utilization_percentage: This is the maximum hourly utilization
     in the usage time (day or month). E.g. if usage record corresponds to
     12/10/2017 and on that for hour 4 and 5, utilization was 100%, this field
     will return 100% for that day.
    :vartype max_utilization_percentage: decimal.Decimal
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
        'reservation_order_id': {'readonly': True},
        'reservation_id': {'readonly': True},
        'sku_name': {'readonly': True},
        'reserved_hours': {'readonly': True},
        'usage_date': {'readonly': True},
        'used_hours': {'readonly': True},
        'min_utilization_percentage': {'readonly': True},
        'avg_utilization_percentage': {'readonly': True},
        'max_utilization_percentage': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'reservation_order_id': {'key': 'properties.reservationOrderId', 'type': 'str'},
        'reservation_id': {'key': 'properties.reservationId', 'type': 'str'},
        'sku_name': {'key': 'properties.skuName', 'type': 'str'},
        'reserved_hours': {'key': 'properties.reservedHours', 'type': 'decimal'},
        'usage_date': {'key': 'properties.usageDate', 'type': 'iso-8601'},
        'used_hours': {'key': 'properties.usedHours', 'type': 'decimal'},
        'min_utilization_percentage': {'key': 'properties.minUtilizationPercentage', 'type': 'decimal'},
        'avg_utilization_percentage': {'key': 'properties.avgUtilizationPercentage', 'type': 'decimal'},
        'max_utilization_percentage': {'key': 'properties.maxUtilizationPercentage', 'type': 'decimal'},
    }

    def __init__(self, **kwargs) -> None:
        super(ReservationSummary, self).__init__(**kwargs)
        self.reservation_order_id = None
        self.reservation_id = None
        self.sku_name = None
        self.reserved_hours = None
        self.usage_date = None
        self.used_hours = None
        self.min_utilization_percentage = None
        self.avg_utilization_percentage = None
        self.max_utilization_percentage = None
