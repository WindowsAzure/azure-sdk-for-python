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


class BillingAccountUpdateProperties(Model):
    """The properties of the billing account that can be updated.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar display_name: The billing account name.
    :vartype display_name: str
    :ivar account_type: The billing account Type. Possible values include:
     'Organization', 'Enrollment'
    :vartype account_type: str or ~azure.mgmt.billing.models.enum
    :param address: The address associated with billing account.
    :type address: ~azure.mgmt.billing.models.Address
    :ivar company: Company Name.
    :vartype company: str
    :ivar country: Country Name.
    :vartype country: str
    :param invoice_sections: The invoice sections associated to the billing
     account. By default this is not populated, unless it's specified in
     $expand.
    :type invoice_sections: list[~azure.mgmt.billing.models.InvoiceSection]
    :param billing_profiles: The billing profiles associated to the billing
     account. By default this is not populated, unless it's specified in
     $expand.
    :type billing_profiles: list[~azure.mgmt.billing.models.BillingProfile]
    :ivar enrollment_details: The details about the associated legacy
     enrollment. By default this is not populated, unless it's specified in
     $expand.
    :vartype enrollment_details: ~azure.mgmt.billing.models.Enrollment
    :param departments: The departments associated to the enrollment.
    :type departments: list[~azure.mgmt.billing.models.Department]
    :param enrollment_accounts: The accounts associated to the enrollment.
    :type enrollment_accounts:
     list[~azure.mgmt.billing.models.EnrollmentAccount]
    :ivar has_read_access: Specifies whether the user has read access on
     billing account.
    :vartype has_read_access: bool
    """

    _validation = {
        'display_name': {'readonly': True},
        'account_type': {'readonly': True},
        'company': {'readonly': True},
        'country': {'readonly': True},
        'enrollment_details': {'readonly': True},
        'has_read_access': {'readonly': True},
    }

    _attribute_map = {
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'account_type': {'key': 'properties.accountType', 'type': 'str'},
        'address': {'key': 'properties.address', 'type': 'Address'},
        'company': {'key': 'properties.company', 'type': 'str'},
        'country': {'key': 'properties.country', 'type': 'str'},
        'invoice_sections': {'key': 'properties.invoiceSections', 'type': '[InvoiceSection]'},
        'billing_profiles': {'key': 'properties.billingProfiles', 'type': '[BillingProfile]'},
        'enrollment_details': {'key': 'properties.enrollmentDetails', 'type': 'Enrollment'},
        'departments': {'key': 'properties.departments', 'type': '[Department]'},
        'enrollment_accounts': {'key': 'properties.enrollmentAccounts', 'type': '[EnrollmentAccount]'},
        'has_read_access': {'key': 'properties.hasReadAccess', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(BillingAccountUpdateProperties, self).__init__(**kwargs)
        self.display_name = None
        self.account_type = None
        self.address = kwargs.get('address', None)
        self.company = None
        self.country = None
        self.invoice_sections = kwargs.get('invoice_sections', None)
        self.billing_profiles = kwargs.get('billing_profiles', None)
        self.enrollment_details = None
        self.departments = kwargs.get('departments', None)
        self.enrollment_accounts = kwargs.get('enrollment_accounts', None)
        self.has_read_access = None
