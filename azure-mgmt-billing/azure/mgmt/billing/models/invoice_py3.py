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


class Invoice(Resource):
    """An invoice resource can be used download a PDF version of an invoice.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param download_url: A secure link to download the PDF version of an
     invoice. The link will cease to work after its expiry time is reached.
    :type download_url: ~azure.mgmt.billing.models.DownloadUrl
    :ivar invoice_period_start_date: The start of the date range covered by
     the invoice.
    :vartype invoice_period_start_date: date
    :ivar invoice_period_end_date: The end of the date range covered by the
     invoice.
    :vartype invoice_period_end_date: date
    :ivar billing_period_ids: Array of billing perdiod ids that the invoice is
     attributed to.
    :vartype billing_period_ids: list[str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'invoice_period_start_date': {'readonly': True},
        'invoice_period_end_date': {'readonly': True},
        'billing_period_ids': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'download_url': {'key': 'properties.downloadUrl', 'type': 'DownloadUrl'},
        'invoice_period_start_date': {'key': 'properties.invoicePeriodStartDate', 'type': 'date'},
        'invoice_period_end_date': {'key': 'properties.invoicePeriodEndDate', 'type': 'date'},
        'billing_period_ids': {'key': 'properties.billingPeriodIds', 'type': '[str]'},
    }

    def __init__(self, *, download_url=None, **kwargs) -> None:
        super(Invoice, self).__init__(**kwargs)
        self.download_url = download_url
        self.invoice_period_start_date = None
        self.invoice_period_end_date = None
        self.billing_period_ids = None
