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


class AddressValidationStatus(str, Enum):

    valid = "Valid"
    invalid = "Invalid"


class ProductType(str, Enum):

    azure_subscription = "AzureSubscription"
    azure_reservation = "AzureReservation"


class TransferStatus(str, Enum):

    pending = "Pending"
    in_progress = "InProgress"
    completed = "Completed"
    completed_with_errors = "CompletedWithErrors"
    failed = "Failed"
    canceled = "Canceled"
    declined = "Declined"


class ProductTransferStatus(str, Enum):

    not_started = "NotStarted"
    in_progress = "InProgress"
    completed = "Completed"
    failed = "Failed"


class EligibleProductType(str, Enum):

    dev_test_azure_subscription = "DevTestAzureSubscription"
    standard_azure_subscription = "StandardAzureSubscription"
    azure_reservation = "AzureReservation"


class SubscriptionTransferValidationErrorCode(str, Enum):

    invalid_source = "InvalidSource"
    subscription_not_active = "SubscriptionNotActive"
    insufficient_permission_on_source = "InsufficientPermissionOnSource"
    insufficient_permission_on_destination = "InsufficientPermissionOnDestination"
    destination_billing_profile_past_due = "DestinationBillingProfilePastDue"
    subscription_type_not_supported = "SubscriptionTypeNotSupported"
    cross_billing_account_not_allowed = "CrossBillingAccountNotAllowed"
    not_available_for_destination_market = "NotAvailableForDestinationMarket"


class AgreementType(str, Enum):

    microsoft_customer_agreement = "MicrosoftCustomerAgreement"
    enterprise_agreement = "EnterpriseAgreement"
    microsoft_online_services_program = "MicrosoftOnlineServicesProgram"
    microsoft_partner_agreement = "MicrosoftPartnerAgreement"


class CustomerType(str, Enum):

    enterprise = "Enterprise"
    individual = "Individual"
    partner = "Partner"


class AccountType(str, Enum):

    enterprise = "Enterprise"
    individual = "Individual"
    partner = "Partner"


class StatusReasonCode(str, Enum):

    past_due = "PastDue"
    spending_limit_reached = "SpendingLimitReached"
    spending_limit_expired = "SpendingLimitExpired"


class SpendingLimit(str, Enum):

    off = "Off"
    on = "On"


class BillingProfileStatus(str, Enum):

    active = "Active"
    disabled = "Disabled"
    warned = "Warned"


class BillingProfileStatusReasonCode(str, Enum):

    past_due = "PastDue"
    spending_limit_reached = "SpendingLimitReached"
    spending_limit_expired = "SpendingLimitExpired"


class BillingProfileSpendingLimit(str, Enum):

    off = "Off"
    on = "On"


class InvoiceStatus(str, Enum):

    due = "Due"
    over_due = "OverDue"
    paid = "Paid"


class InvoiceType(str, Enum):

    azure_service = "AzureService"
    azure_marketplace = "AzureMarketplace"
    azure_support = "AzureSupport"


class DocumentType(str, Enum):

    invoice = "Invoice"
    void_note = "VoidNote"
    tax_receipt = "TaxReceipt"
    credit_note = "CreditNote"


class PaymentMethodFamily(str, Enum):

    credits = "Credits"
    check_wire = "CheckWire"
    credit_card = "CreditCard"
    none = "None"


class ProductStatusType(str, Enum):

    active = "Active"
    inactive = "Inactive"
    past_due = "PastDue"
    expiring = "Expiring"
    expired = "Expired"
    disabled = "Disabled"
    cancelled = "Cancelled"
    auto_renew = "AutoRenew"


class BillingFrequency(str, Enum):

    one_time = "OneTime"
    monthly = "Monthly"
    usage_based = "UsageBased"


class ProductTransferValidationErrorCode(str, Enum):

    invalid_source = "InvalidSource"
    product_not_active = "ProductNotActive"
    insufficient_permission_on_source = "InsufficientPermissionOnSource"
    insufficient_permission_on_destination = "InsufficientPermissionOnDestination"
    destination_billing_profile_past_due = "DestinationBillingProfilePastDue"
    product_type_not_supported = "ProductTypeNotSupported"
    cross_billing_account_not_allowed = "CrossBillingAccountNotAllowed"
    not_available_for_destination_market = "NotAvailableForDestinationMarket"
    one_time_purchase_product_transfer_not_allowed = "OneTimePurchaseProductTransferNotAllowed"


class BillingSubscriptionStatusType(str, Enum):

    active = "Active"
    inactive = "Inactive"
    abandoned = "Abandoned"
    deleted = "Deleted"
    warning = "Warning"


class TransactionTypeKind(str, Enum):

    all = "all"
    reservation = "reservation"


class ReservationType(str, Enum):

    purchase = "Purchase"
    usage_charge = "Usage Charge"


class MarketplacePurchasesPolicy(str, Enum):

    all_allowed = "AllAllowed"
    only_free_allowed = "OnlyFreeAllowed"
    not_allowed = "NotAllowed"


class ReservationPurchasesPolicy(str, Enum):

    allowed = "Allowed"
    not_allowed = "NotAllowed"


class ViewChargesPolicy(str, Enum):

    allowed = "Allowed"
    not_allowed = "NotAllowed"


class ViewCharges(str, Enum):

    allowed = "Allowed"
    not_allowed = "NotAllowed"


class PaymentMethodType(str, Enum):

    credits = "Credits"
    cheque_wire = "ChequeWire"


class UpdateAutoRenew(str, Enum):

    true = "true"
    false = "false"


class Category(str, Enum):

    microsoft_customer_agreement = "MicrosoftCustomerAgreement"
    affiliate_purchase_terms = "AffiliatePurchaseTerms"
    other = "Other"


class AcceptanceMode(str, Enum):

    click_to_accept = "ClickToAccept"
    esign_embedded = "ESignEmbedded"
    esign_offline = "ESignOffline"
