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


class ExtendedErrorInfo(Model):
    """ExtendedErrorInfo.

    :param code: Possible values include: 'NotSpecified',
     'InternalServerError', 'ServerTimeout', 'AuthorizationFailed',
     'BadRequest', 'ClientCertificateThumbprintNotSet',
     'InvalidRequestContent', 'OperationFailed', 'HttpMethodNotSupported',
     'InvalidRequestUri', 'MissingTenantId', 'InvalidTenantId',
     'InvalidReservationOrderId', 'InvalidReservationId',
     'ReservationIdNotInReservationOrder', 'ReservationOrderNotFound',
     'InvalidSubscriptionId', 'InvalidAccessToken', 'InvalidLocationId',
     'UnauthenticatedRequestsThrottled', 'InvalidHealthCheckType', 'Forbidden',
     'BillingScopeIdCannotBeChanged',
     'AppliedScopesNotAssociatedWithCommerceAccount',
     'PatchValuesSameAsExisting', 'RoleAssignmentCreationFailed',
     'ReservationOrderCreationFailed', 'ReservationOrderNotEnabled',
     'CapacityUpdateScopesFailed', 'UnsupportedReservationTerm',
     'ReservationOrderIdAlreadyExists', 'RiskCheckFailed', 'CreateQuoteFailed',
     'ActivateQuoteFailed', 'NonsupportedAccountId',
     'PaymentInstrumentNotFound', 'MissingAppliedScopesForSingle',
     'NoValidReservationsToReRate', 'ReRateOnlyAllowedForEA',
     'OperationCannotBePerformedInCurrentState',
     'InvalidSingleAppliedScopesCount', 'InvalidFulfillmentRequestParameters',
     'NotSupportedCountry', 'InvalidRefundQuantity', 'PurchaseError',
     'BillingCustomerInputError', 'BillingPaymentInstrumentSoftError',
     'BillingPaymentInstrumentHardError', 'BillingTransientError',
     'BillingError', 'FulfillmentConfigurationError',
     'FulfillmentOutOfStockError', 'FulfillmentTransientError',
     'FulfillmentError', 'CalculatePriceFailed'
    :type code: str or ~azure.mgmt.reservations.models.enum
    :param message:
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ExtendedErrorInfo, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)
