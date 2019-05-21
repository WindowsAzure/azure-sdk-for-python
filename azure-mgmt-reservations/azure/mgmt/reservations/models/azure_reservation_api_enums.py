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

from enum import Enum


class ReservationStatusCode(str, Enum):

    none = "None"
    pending = "Pending"
    active = "Active"
    purchase_error = "PurchaseError"
    payment_instrument_error = "PaymentInstrumentError"
    split = "Split"
    merged = "Merged"
    expired = "Expired"
    succeeded = "Succeeded"


class ErrorResponseCode(str, Enum):

    not_specified = "NotSpecified"
    internal_server_error = "InternalServerError"
    server_timeout = "ServerTimeout"
    authorization_failed = "AuthorizationFailed"
    bad_request = "BadRequest"
    client_certificate_thumbprint_not_set = "ClientCertificateThumbprintNotSet"
    invalid_request_content = "InvalidRequestContent"
    operation_failed = "OperationFailed"
    http_method_not_supported = "HttpMethodNotSupported"
    invalid_request_uri = "InvalidRequestUri"
    missing_tenant_id = "MissingTenantId"
    invalid_tenant_id = "InvalidTenantId"
    invalid_reservation_order_id = "InvalidReservationOrderId"
    invalid_reservation_id = "InvalidReservationId"
    reservation_id_not_in_reservation_order = "ReservationIdNotInReservationOrder"
    reservation_order_not_found = "ReservationOrderNotFound"
    invalid_subscription_id = "InvalidSubscriptionId"
    invalid_access_token = "InvalidAccessToken"
    invalid_location_id = "InvalidLocationId"
    unauthenticated_requests_throttled = "UnauthenticatedRequestsThrottled"
    invalid_health_check_type = "InvalidHealthCheckType"
    forbidden = "Forbidden"
    billing_scope_id_cannot_be_changed = "BillingScopeIdCannotBeChanged"
    applied_scopes_not_associated_with_commerce_account = "AppliedScopesNotAssociatedWithCommerceAccount"
    patch_values_same_as_existing = "PatchValuesSameAsExisting"
    role_assignment_creation_failed = "RoleAssignmentCreationFailed"
    reservation_order_creation_failed = "ReservationOrderCreationFailed"
    reservation_order_not_enabled = "ReservationOrderNotEnabled"
    capacity_update_scopes_failed = "CapacityUpdateScopesFailed"
    unsupported_reservation_term = "UnsupportedReservationTerm"
    reservation_order_id_already_exists = "ReservationOrderIdAlreadyExists"
    risk_check_failed = "RiskCheckFailed"
    create_quote_failed = "CreateQuoteFailed"
    activate_quote_failed = "ActivateQuoteFailed"
    nonsupported_account_id = "NonsupportedAccountId"
    payment_instrument_not_found = "PaymentInstrumentNotFound"
    missing_applied_scopes_for_single = "MissingAppliedScopesForSingle"
    no_valid_reservations_to_re_rate = "NoValidReservationsToReRate"
    re_rate_only_allowed_for_ea = "ReRateOnlyAllowedForEA"
    operation_cannot_be_performed_in_current_state = "OperationCannotBePerformedInCurrentState"
    invalid_single_applied_scopes_count = "InvalidSingleAppliedScopesCount"
    invalid_fulfillment_request_parameters = "InvalidFulfillmentRequestParameters"
    not_supported_country = "NotSupportedCountry"
    invalid_refund_quantity = "InvalidRefundQuantity"
    purchase_error = "PurchaseError"
    billing_customer_input_error = "BillingCustomerInputError"
    billing_payment_instrument_soft_error = "BillingPaymentInstrumentSoftError"
    billing_payment_instrument_hard_error = "BillingPaymentInstrumentHardError"
    billing_transient_error = "BillingTransientError"
    billing_error = "BillingError"
    fulfillment_configuration_error = "FulfillmentConfigurationError"
    fulfillment_out_of_stock_error = "FulfillmentOutOfStockError"
    fulfillment_transient_error = "FulfillmentTransientError"
    fulfillment_error = "FulfillmentError"
    calculate_price_failed = "CalculatePriceFailed"


class ReservationTerm(str, Enum):

    p1_y = "P1Y"
    p3_y = "P3Y"


class ReservedResourceType(str, Enum):

    virtual_machines = "VirtualMachines"
    sql_databases = "SqlDatabases"
    suse_linux = "SuseLinux"
    cosmos_db = "CosmosDb"


class InstanceFlexibility(str, Enum):

    on = "On"
    off = "Off"


class AppliedScopeType(str, Enum):

    single = "Single"
    shared = "Shared"
