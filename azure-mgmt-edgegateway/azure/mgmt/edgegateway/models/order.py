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

from .arm_base_model import ARMBaseModel


class Order(ARMBaseModel):
    """The order details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The path ID that uniquely identifies the object.
    :vartype id: str
    :ivar name: The object name.
    :vartype name: str
    :ivar type: The hierarchical type of the object.
    :vartype type: str
    :param contact_information: Required. The contact details.
    :type contact_information: ~azure.mgmt.edgegateway.models.ContactDetails
    :param shipping_address: Required. The shipping address.
    :type shipping_address: ~azure.mgmt.edgegateway.models.Address
    :param current_status: Current status of the order.
    :type current_status: ~azure.mgmt.edgegateway.models.OrderStatus
    :ivar order_history: List of status changes in the order.
    :vartype order_history: list[~azure.mgmt.edgegateway.models.OrderStatus]
    :ivar serial_number: Serial number of the device.
    :vartype serial_number: str
    :ivar delivery_tracking_info: Tracking information for the package
     delivered to the customer whether it has an original or a replacement
     device.
    :vartype delivery_tracking_info:
     list[~azure.mgmt.edgegateway.models.TrackingInfo]
    :ivar return_tracking_info: Tracking information for the package returned
     from the customer whether it has an original or a replacement device.
    :vartype return_tracking_info:
     list[~azure.mgmt.edgegateway.models.TrackingInfo]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'contact_information': {'required': True},
        'shipping_address': {'required': True},
        'order_history': {'readonly': True},
        'serial_number': {'readonly': True},
        'delivery_tracking_info': {'readonly': True},
        'return_tracking_info': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'contact_information': {'key': 'properties.contactInformation', 'type': 'ContactDetails'},
        'shipping_address': {'key': 'properties.shippingAddress', 'type': 'Address'},
        'current_status': {'key': 'properties.currentStatus', 'type': 'OrderStatus'},
        'order_history': {'key': 'properties.orderHistory', 'type': '[OrderStatus]'},
        'serial_number': {'key': 'properties.serialNumber', 'type': 'str'},
        'delivery_tracking_info': {'key': 'properties.deliveryTrackingInfo', 'type': '[TrackingInfo]'},
        'return_tracking_info': {'key': 'properties.returnTrackingInfo', 'type': '[TrackingInfo]'},
    }

    def __init__(self, **kwargs):
        super(Order, self).__init__(**kwargs)
        self.contact_information = kwargs.get('contact_information', None)
        self.shipping_address = kwargs.get('shipping_address', None)
        self.current_status = kwargs.get('current_status', None)
        self.order_history = None
        self.serial_number = None
        self.delivery_tracking_info = None
        self.return_tracking_info = None
