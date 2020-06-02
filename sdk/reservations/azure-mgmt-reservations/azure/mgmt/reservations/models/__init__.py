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
    from ._models_py3 import Actions
    from ._models_py3 import AppliedReservationList
    from ._models_py3 import AppliedReservations
    from ._models_py3 import AqiSettings
    from ._models_py3 import AutoQuotaIncreaseDetail
    from ._models_py3 import CalculatePriceResponse
    from ._models_py3 import CalculatePriceResponseProperties
    from ._models_py3 import CalculatePriceResponsePropertiesBillingCurrencyTotal
    from ._models_py3 import CalculatePriceResponsePropertiesPricingCurrencyTotal
    from ._models_py3 import Catalog
    from ._models_py3 import CreateGenericQuotaRequestParameters
    from ._models_py3 import CurrentQuotaLimit
    from ._models_py3 import CurrentQuotaLimitBase
    from ._models_py3 import EmailAction
    from ._models_py3 import EmailActions
    from ._models_py3 import Error, ErrorException
    from ._models_py3 import ExceptionResponse, ExceptionResponseException
    from ._models_py3 import ExtendedErrorInfo
    from ._models_py3 import ExtendedStatusInfo
    from ._models_py3 import MergeRequest
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationResponse
    from ._models_py3 import Patch
    from ._models_py3 import PatchPropertiesRenewProperties
    from ._models_py3 import PaymentDetail
    from ._models_py3 import PhoneAction
    from ._models_py3 import Price
    from ._models_py3 import Properties
    from ._models_py3 import PurchaseRequest
    from ._models_py3 import PurchaseRequestPropertiesReservedResourceProperties
    from ._models_py3 import QuotaLimitsResponse
    from ._models_py3 import QuotaProperties
    from ._models_py3 import QuotaRequestDetails
    from ._models_py3 import QuotaRequestOneResourceSubmitResponse
    from ._models_py3 import QuotaRequestProperties
    from ._models_py3 import QuotaRequestSubmitResponse
    from ._models_py3 import QuotaRequestSubmitResponse201
    from ._models_py3 import RenewPropertiesResponse
    from ._models_py3 import RenewPropertiesResponseBillingCurrencyTotal
    from ._models_py3 import RenewPropertiesResponsePricingCurrencyTotal
    from ._models_py3 import ReservationMergeProperties
    from ._models_py3 import ReservationOrderBillingPlanInformation
    from ._models_py3 import ReservationOrderResponse
    from ._models_py3 import ReservationProperties
    from ._models_py3 import ReservationResponse
    from ._models_py3 import ReservationSplitProperties
    from ._models_py3 import ResourceName
    from ._models_py3 import ScopeProperties
    from ._models_py3 import ServiceError
    from ._models_py3 import ServiceErrorDetail
    from ._models_py3 import SkuName
    from ._models_py3 import SkuProperty
    from ._models_py3 import SkuRestriction
    from ._models_py3 import SplitRequest
    from ._models_py3 import SubRequest
    from ._models_py3 import SubscriptionScopeProperties
    from ._models_py3 import SupportRequestAction
except (SyntaxError, ImportError):
    from ._models import Actions
    from ._models import AppliedReservationList
    from ._models import AppliedReservations
    from ._models import AqiSettings
    from ._models import AutoQuotaIncreaseDetail
    from ._models import CalculatePriceResponse
    from ._models import CalculatePriceResponseProperties
    from ._models import CalculatePriceResponsePropertiesBillingCurrencyTotal
    from ._models import CalculatePriceResponsePropertiesPricingCurrencyTotal
    from ._models import Catalog
    from ._models import CreateGenericQuotaRequestParameters
    from ._models import CurrentQuotaLimit
    from ._models import CurrentQuotaLimitBase
    from ._models import EmailAction
    from ._models import EmailActions
    from ._models import Error, ErrorException
    from ._models import ExceptionResponse, ExceptionResponseException
    from ._models import ExtendedErrorInfo
    from ._models import ExtendedStatusInfo
    from ._models import MergeRequest
    from ._models import OperationDisplay
    from ._models import OperationResponse
    from ._models import Patch
    from ._models import PatchPropertiesRenewProperties
    from ._models import PaymentDetail
    from ._models import PhoneAction
    from ._models import Price
    from ._models import Properties
    from ._models import PurchaseRequest
    from ._models import PurchaseRequestPropertiesReservedResourceProperties
    from ._models import QuotaLimitsResponse
    from ._models import QuotaProperties
    from ._models import QuotaRequestDetails
    from ._models import QuotaRequestOneResourceSubmitResponse
    from ._models import QuotaRequestProperties
    from ._models import QuotaRequestSubmitResponse
    from ._models import QuotaRequestSubmitResponse201
    from ._models import RenewPropertiesResponse
    from ._models import RenewPropertiesResponseBillingCurrencyTotal
    from ._models import RenewPropertiesResponsePricingCurrencyTotal
    from ._models import ReservationMergeProperties
    from ._models import ReservationOrderBillingPlanInformation
    from ._models import ReservationOrderResponse
    from ._models import ReservationProperties
    from ._models import ReservationResponse
    from ._models import ReservationSplitProperties
    from ._models import ResourceName
    from ._models import ScopeProperties
    from ._models import ServiceError
    from ._models import ServiceErrorDetail
    from ._models import SkuName
    from ._models import SkuProperty
    from ._models import SkuRestriction
    from ._models import SplitRequest
    from ._models import SubRequest
    from ._models import SubscriptionScopeProperties
    from ._models import SupportRequestAction
from ._paged_models import CurrentQuotaLimitBasePaged
from ._paged_models import OperationResponsePaged
from ._paged_models import QuotaRequestDetailsPaged
from ._paged_models import ReservationOrderResponsePaged
from ._paged_models import ReservationResponsePaged
from ._azure_reservation_api_enums import (
    ReservationStatusCode,
    ErrorResponseCode,
    ReservationBillingPlan,
    ReservationTerm,
    PaymentStatus,
    ReservedResourceType,
    InstanceFlexibility,
    AppliedScopeType,
)

__all__ = [
    'Actions',
    'AppliedReservationList',
    'AppliedReservations',
    'AqiSettings',
    'AutoQuotaIncreaseDetail',
    'CalculatePriceResponse',
    'CalculatePriceResponseProperties',
    'CalculatePriceResponsePropertiesBillingCurrencyTotal',
    'CalculatePriceResponsePropertiesPricingCurrencyTotal',
    'Catalog',
    'CreateGenericQuotaRequestParameters',
    'CurrentQuotaLimit',
    'CurrentQuotaLimitBase',
    'EmailAction',
    'EmailActions',
    'Error', 'ErrorException',
    'ExceptionResponse', 'ExceptionResponseException',
    'ExtendedErrorInfo',
    'ExtendedStatusInfo',
    'MergeRequest',
    'OperationDisplay',
    'OperationResponse',
    'Patch',
    'PatchPropertiesRenewProperties',
    'PaymentDetail',
    'PhoneAction',
    'Price',
    'Properties',
    'PurchaseRequest',
    'PurchaseRequestPropertiesReservedResourceProperties',
    'QuotaLimitsResponse',
    'QuotaProperties',
    'QuotaRequestDetails',
    'QuotaRequestOneResourceSubmitResponse',
    'QuotaRequestProperties',
    'QuotaRequestSubmitResponse',
    'QuotaRequestSubmitResponse201',
    'RenewPropertiesResponse',
    'RenewPropertiesResponseBillingCurrencyTotal',
    'RenewPropertiesResponsePricingCurrencyTotal',
    'ReservationMergeProperties',
    'ReservationOrderBillingPlanInformation',
    'ReservationOrderResponse',
    'ReservationProperties',
    'ReservationResponse',
    'ReservationSplitProperties',
    'ResourceName',
    'ScopeProperties',
    'ServiceError',
    'ServiceErrorDetail',
    'SkuName',
    'SkuProperty',
    'SkuRestriction',
    'SplitRequest',
    'SubRequest',
    'SubscriptionScopeProperties',
    'SupportRequestAction',
    'CurrentQuotaLimitBasePaged',
    'QuotaRequestDetailsPaged',
    'ReservationResponsePaged',
    'ReservationOrderResponsePaged',
    'OperationResponsePaged',
    'ReservationStatusCode',
    'ErrorResponseCode',
    'ReservationBillingPlan',
    'ReservationTerm',
    'PaymentStatus',
    'ReservedResourceType',
    'InstanceFlexibility',
    'AppliedScopeType',
]
