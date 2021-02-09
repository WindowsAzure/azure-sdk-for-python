# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: sample_recognize_invoices.py

DESCRIPTION:
    This sample demonstrates how to recognize fields from invoices.

    See fields found on a invoice here:
    https://aka.ms/formrecognizer/invoicefields

USAGE:
    python sample_recognize_invoices.py

    Set the environment variables with your own values before running the sample:
    1) AZURE_FORM_RECOGNIZER_ENDPOINT - the endpoint to your Cognitive Services resource.
    2) AZURE_FORM_RECOGNIZER_KEY - your Form Recognizer API key
"""

import os


class RecognizeInvoiceSample(object):

    def recognize_invoice(self):
        path_to_sample_forms = os.path.abspath(os.path.join(os.path.abspath(__file__),
                                                            "..", "./sample_forms/forms/sample_invoice.jpg"))

        # [START recognize_invoices]
        from azure.core.credentials import AzureKeyCredential
        from azure.ai.formrecognizer import FormRecognizerClient

        endpoint = os.environ["AZURE_FORM_RECOGNIZER_ENDPOINT"]
        key = os.environ["AZURE_FORM_RECOGNIZER_KEY"]

        form_recognizer_client = FormRecognizerClient(
            endpoint=endpoint, credential=AzureKeyCredential(key)
        )
        with open(path_to_sample_forms, "rb") as f:
            poller = form_recognizer_client.begin_recognize_invoices(invoice=f, locale="en-US")
        invoices = poller.result()

        for idx, invoice in enumerate(invoices):
            print("--------Recognizing invoice #{}--------".format(idx+1))
            vendor_name = invoice.fields.get("VendorName")
            if vendor_name:
                print("Vendor Name: {} has confidence: {}".format(vendor_name.value, vendor_name.confidence))
            vendor_address = invoice.fields.get("VendorAddress")
            if vendor_address:
                print("Vendor Address: {} has confidence: {}".format(vendor_address.value, vendor_address.confidence))
            vendor_address_recipient = invoice.fields.get("VendorAddressRecipient")
            if vendor_address_recipient:
                print("Vendor Address Recipient: {} has confidence: {}".format(vendor_address_recipient.value, vendor_address_recipient.confidence))
            customer_name = invoice.fields.get("CustomerName")
            if customer_name:
                print("Customer Name: {} has confidence: {}".format(customer_name.value, customer_name.confidence))
            customer_id = invoice.fields.get("CustomerId")
            if customer_id:
                print("Customer Id: {} has confidence: {}".format(customer_id.value, customer_id.confidence))
            customer_address = invoice.fields.get("CustomerAddress")
            if customer_address:
                print("Customer Address: {} has confidence: {}".format(customer_address.value, customer_address.confidence))
            customer_address_recipient = invoice.fields.get("CustomerAddressRecipient")
            if customer_address_recipient:
                print("Customer Address Recipient: {} has confidence: {}".format(customer_address_recipient.value, customer_address_recipient.confidence))
            invoice_id = invoice.fields.get("InvoiceId")
            if invoice_id:
                print("Invoice Id: {} has confidence: {}".format(invoice_id.value, invoice_id.confidence))
            invoice_date = invoice.fields.get("InvoiceDate")
            if invoice_date:
                print("Invoice Date: {} has confidence: {}".format(invoice_date.value, invoice_date.confidence))
            invoice_total = invoice.fields.get("InvoiceTotal")
            if invoice_total:
                print("Invoice Total: {} has confidence: {}".format(invoice_total.value, invoice_total.confidence))
            due_date = invoice.fields.get("DueDate")
            if due_date:
                print("Due Date: {} has confidence: {}".format(due_date.value, due_date.confidence))
            purchase_order = invoice.fields.get("PurchaseOrder")
            if purchase_order:
                print("Purchase Order: {} has confidence: {}".format(purchase_order.value, purchase_order.confidence))
            billing_address = invoice.fields.get("BillingAddress")
            if billing_address:
                print("Billing Address: {} has confidence: {}".format(billing_address.value, billing_address.confidence))
            billing_address_recipient = invoice.fields.get("BillingAddressRecipient")
            if billing_address_recipient:
                print("Billing Address Recipient: {} has confidence: {}".format(billing_address_recipient.value, billing_address_recipient.confidence))
            shipping_address = invoice.fields.get("ShippingAddress")
            if shipping_address:
                print("Shipping Address: {} has confidence: {}".format(shipping_address.value, shipping_address.confidence))
            shipping_address_recipient = invoice.fields.get("ShippingAddressRecipient")
            if shipping_address_recipient:
                print("Shipping Address Recipient: {} has confidence: {}".format(shipping_address_recipient.value, shipping_address_recipient.confidence))
            subtotal = invoice.fields.get("SubTotal")
            if subtotal:
                print("Subtotal: {} has confidence: {}".format(subtotal.value, subtotal.confidence))
            total_tax = invoice.fields.get("TotalTax")
            if total_tax:
                print("Total Tax: {} has confidence: {}".format(total_tax.value, total_tax.confidence))
            previous_unpaid_balance = invoice.fields.get("PreviousUnpaidBalance")
            if previous_unpaid_balance:
                print("Previous Unpaid Balance: {} has confidence: {}".format(previous_unpaid_balance.value, previous_unpaid_balance.confidence))
            amount_due = invoice.fields.get("AmountDue")
            if amount_due:
                print("Amount Due: {} has confidence: {}".format(amount_due.value, amount_due.confidence))
            service_start_date = invoice.fields.get("ServiceStartDate")
            if service_start_date:
                print("Service Start Date: {} has confidence: {}".format(service_start_date.value, service_start_date.confidence))
            service_end_date = invoice.fields.get("ServiceEndDate")
            if service_end_date:
                print("Service End Date: {} has confidence: {}".format(service_end_date.value, service_end_date.confidence))
            service_address = invoice.fields.get("ServiceAddress")
            if service_address:
                print("Service Address: {} has confidence: {}".format(service_address.value, service_address.confidence))
            service_address_recipient = invoice.fields.get("ServiceAddressRecipient")
            if service_address_recipient:
                print("Service Address Recipient: {} has confidence: {}".format(service_address_recipient.value, service_address_recipient.confidence))
            remittance_address = invoice.fields.get("RemittanceAddress")
            if remittance_address:
                print("Remittance Address: {} has confidence: {}".format(remittance_address.value, remittance_address.confidence))
            remittance_address_recipient = invoice.fields.get("RemittanceAddressRecipient")
            if remittance_address_recipient:
                print("Remittance Address Recipient: {} has confidence: {}".format(remittance_address_recipient.value, remittance_address_recipient.confidence))
        # [END recognize_invoices]

if __name__ == '__main__':
    sample = RecognizeInvoiceSample()
    sample.recognize_invoice()
