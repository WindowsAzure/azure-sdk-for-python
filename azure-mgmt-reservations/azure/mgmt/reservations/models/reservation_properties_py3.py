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


class ReservationProperties(Model):
    """ReservationProperties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param reserved_resource_type: Possible values include: 'VirtualMachines',
     'SqlDatabases', 'SuseLinux'
    :type reserved_resource_type: str or
     ~azure.mgmt.reservations.models.ReservedResourceType
    :param instance_flexibility: Possible values include: 'On', 'Off',
     'NotSupported'
    :type instance_flexibility: str or
     ~azure.mgmt.reservations.models.InstanceFlexibility
    :param display_name: Friendly name for user to easily identify the
     reservation
    :type display_name: str
    :param applied_scopes:
    :type applied_scopes: list[str]
    :param applied_scope_type: Possible values include: 'Single', 'Shared'
    :type applied_scope_type: str or
     ~azure.mgmt.reservations.models.AppliedScopeType
    :param quantity: Quantity of the SKUs that are part of the Reservation.
    :type quantity: int
    :param provisioning_state: Current state of the reservation.
    :type provisioning_state: str
    :param effective_date_time: DateTime of the Reservation starting when this
     version is effective from.
    :type effective_date_time: datetime
    :ivar last_updated_date_time: DateTime of the last time the Reservation
     was updated.
    :vartype last_updated_date_time: datetime
    :param expiry_date: This is the date when the Reservation will expire.
    :type expiry_date: date
    :param sku_description: Description of the SKU in english.
    :type sku_description: str
    :param extended_status_info:
    :type extended_status_info:
     ~azure.mgmt.reservations.models.ExtendedStatusInfo
    :param split_properties:
    :type split_properties:
     ~azure.mgmt.reservations.models.ReservationSplitProperties
    :param merge_properties:
    :type merge_properties:
     ~azure.mgmt.reservations.models.ReservationMergeProperties
    """

    _validation = {
        'last_updated_date_time': {'readonly': True},
    }

    _attribute_map = {
        'reserved_resource_type': {'key': 'reservedResourceType', 'type': 'str'},
        'instance_flexibility': {'key': 'instanceFlexibility', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'applied_scopes': {'key': 'appliedScopes', 'type': '[str]'},
        'applied_scope_type': {'key': 'appliedScopeType', 'type': 'str'},
        'quantity': {'key': 'quantity', 'type': 'int'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'effective_date_time': {'key': 'effectiveDateTime', 'type': 'iso-8601'},
        'last_updated_date_time': {'key': 'lastUpdatedDateTime', 'type': 'iso-8601'},
        'expiry_date': {'key': 'expiryDate', 'type': 'date'},
        'sku_description': {'key': 'skuDescription', 'type': 'str'},
        'extended_status_info': {'key': 'extendedStatusInfo', 'type': 'ExtendedStatusInfo'},
        'split_properties': {'key': 'splitProperties', 'type': 'ReservationSplitProperties'},
        'merge_properties': {'key': 'mergeProperties', 'type': 'ReservationMergeProperties'},
    }

    def __init__(self, *, reserved_resource_type=None, instance_flexibility=None, display_name: str=None, applied_scopes=None, applied_scope_type=None, quantity: int=None, provisioning_state: str=None, effective_date_time=None, expiry_date=None, sku_description: str=None, extended_status_info=None, split_properties=None, merge_properties=None, **kwargs) -> None:
        super(ReservationProperties, self).__init__(**kwargs)
        self.reserved_resource_type = reserved_resource_type
        self.instance_flexibility = instance_flexibility
        self.display_name = display_name
        self.applied_scopes = applied_scopes
        self.applied_scope_type = applied_scope_type
        self.quantity = quantity
        self.provisioning_state = provisioning_state
        self.effective_date_time = effective_date_time
        self.last_updated_date_time = None
        self.expiry_date = expiry_date
        self.sku_description = sku_description
        self.extended_status_info = extended_status_info
        self.split_properties = split_properties
        self.merge_properties = merge_properties
