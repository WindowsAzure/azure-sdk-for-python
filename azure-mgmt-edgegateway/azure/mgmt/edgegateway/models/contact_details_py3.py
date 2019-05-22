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


class ContactDetails(Model):
    """Contains all the contact details of the customer.

    All required parameters must be populated in order to send to Azure.

    :param contact_person: Required. The contact person name.
    :type contact_person: str
    :param company_name: Required. The name of the company.
    :type company_name: str
    :param phone: Required. The phone number.
    :type phone: str
    :param email_list: Required. The email list.
    :type email_list: list[str]
    """

    _validation = {
        'contact_person': {'required': True},
        'company_name': {'required': True},
        'phone': {'required': True},
        'email_list': {'required': True},
    }

    _attribute_map = {
        'contact_person': {'key': 'contactPerson', 'type': 'str'},
        'company_name': {'key': 'companyName', 'type': 'str'},
        'phone': {'key': 'phone', 'type': 'str'},
        'email_list': {'key': 'emailList', 'type': '[str]'},
    }

    def __init__(self, *, contact_person: str, company_name: str, phone: str, email_list, **kwargs) -> None:
        super(ContactDetails, self).__init__(**kwargs)
        self.contact_person = contact_person
        self.company_name = company_name
        self.phone = phone
        self.email_list = email_list
