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

try:
    from .sku_name_py3 import SkuName
    from .sku_property_py3 import SkuProperty
    from .sku_restriction_py3 import SkuRestriction
    from .catalog_py3 import Catalog
    from .extended_status_info_py3 import ExtendedStatusInfo
    from .reservation_split_properties_py3 import ReservationSplitProperties
    from .reservation_merge_properties_py3 import ReservationMergeProperties
    from .purchase_request_properties_reserved_resource_properties_py3 import PurchaseRequestPropertiesReservedResourceProperties
    from .purchase_request_py3 import PurchaseRequest
    from .renew_properties_response_locked_price_total_py3 import RenewPropertiesResponseLockedPriceTotal
    from .renew_properties_response_links_py3 import RenewPropertiesResponseLinks
    from .renew_properties_response_py3 import RenewPropertiesResponse
    from .reservation_properties_py3 import ReservationProperties
    from .reservation_response_py3 import ReservationResponse
    from .reservation_order_response_py3 import ReservationOrderResponse
    from .calculate_price_response_properties_billing_currency_total_py3 import CalculatePriceResponsePropertiesBillingCurrencyTotal
    from .calculate_price_response_properties_pricing_currency_total_py3 import CalculatePriceResponsePropertiesPricingCurrencyTotal
    from .calculate_price_response_properties_py3 import CalculatePriceResponseProperties
    from .calculate_price_response_py3 import CalculatePriceResponse
    from .merge_request_py3 import MergeRequest
    from .patch_py3 import Patch
    from .split_request_py3 import SplitRequest
    from .extended_error_info_py3 import ExtendedErrorInfo
    from .error_py3 import Error, ErrorException
    from .applied_reservation_list_py3 import AppliedReservationList
    from .applied_reservations_py3 import AppliedReservations
    from .operation_display_py3 import OperationDisplay
    from .operation_response_py3 import OperationResponse
except (SyntaxError, ImportError):
    from .sku_name import SkuName
    from .sku_property import SkuProperty
    from .sku_restriction import SkuRestriction
    from .catalog import Catalog
    from .extended_status_info import ExtendedStatusInfo
    from .reservation_split_properties import ReservationSplitProperties
    from .reservation_merge_properties import ReservationMergeProperties
    from .purchase_request_properties_reserved_resource_properties import PurchaseRequestPropertiesReservedResourceProperties
    from .purchase_request import PurchaseRequest
    from .renew_properties_response_locked_price_total import RenewPropertiesResponseLockedPriceTotal
    from .renew_properties_response_links import RenewPropertiesResponseLinks
    from .renew_properties_response import RenewPropertiesResponse
    from .reservation_properties import ReservationProperties
    from .reservation_response import ReservationResponse
    from .reservation_order_response import ReservationOrderResponse
    from .calculate_price_response_properties_billing_currency_total import CalculatePriceResponsePropertiesBillingCurrencyTotal
    from .calculate_price_response_properties_pricing_currency_total import CalculatePriceResponsePropertiesPricingCurrencyTotal
    from .calculate_price_response_properties import CalculatePriceResponseProperties
    from .calculate_price_response import CalculatePriceResponse
    from .merge_request import MergeRequest
    from .patch import Patch
    from .split_request import SplitRequest
    from .extended_error_info import ExtendedErrorInfo
    from .error import Error, ErrorException
    from .applied_reservation_list import AppliedReservationList
    from .applied_reservations import AppliedReservations
    from .operation_display import OperationDisplay
    from .operation_response import OperationResponse
from .reservation_order_response_paged import ReservationOrderResponsePaged
from .reservation_response_paged import ReservationResponsePaged
from .operation_response_paged import OperationResponsePaged
from .azure_reservation_api_enums import (
    ReservationStatusCode,
    ErrorResponseCode,
    ReservationTerm,
    ReservedResourceType,
    InstanceFlexibility,
    AppliedScopeType,
)

__all__ = [
    'SkuName',
    'SkuProperty',
    'SkuRestriction',
    'Catalog',
    'ExtendedStatusInfo',
    'ReservationSplitProperties',
    'ReservationMergeProperties',
    'PurchaseRequestPropertiesReservedResourceProperties',
    'PurchaseRequest',
    'RenewPropertiesResponseLockedPriceTotal',
    'RenewPropertiesResponseLinks',
    'RenewPropertiesResponse',
    'ReservationProperties',
    'ReservationResponse',
    'ReservationOrderResponse',
    'CalculatePriceResponsePropertiesBillingCurrencyTotal',
    'CalculatePriceResponsePropertiesPricingCurrencyTotal',
    'CalculatePriceResponseProperties',
    'CalculatePriceResponse',
    'MergeRequest',
    'Patch',
    'SplitRequest',
    'ExtendedErrorInfo',
    'Error', 'ErrorException',
    'AppliedReservationList',
    'AppliedReservations',
    'OperationDisplay',
    'OperationResponse',
    'ReservationOrderResponsePaged',
    'ReservationResponsePaged',
    'OperationResponsePaged',
    'ReservationStatusCode',
    'ErrorResponseCode',
    'ReservationTerm',
    'ReservedResourceType',
    'InstanceFlexibility',
    'AppliedScopeType',
]
