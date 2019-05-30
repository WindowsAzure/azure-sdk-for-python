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


class Address(Model):
    """Address details.

    :param first_name: First Name.
    :type first_name: str
    :param last_name: Last Name.
    :type last_name: str
    :param company_name: Company Name.
    :type company_name: str
    :param address_line1: Address Line1.
    :type address_line1: str
    :param address_line2: Address Line2.
    :type address_line2: str
    :param address_line3: Address Line3.
    :type address_line3: str
    :param city: Address City.
    :type city: str
    :param region: Address Region.
    :type region: str
    :param country: Country code uses ISO2, 2-digit format.
    :type country: str
    :param postal_code: Address Postal Code.
    :type postal_code: str
    """

    _attribute_map = {
        'first_name': {'key': 'firstName', 'type': 'str'},
        'last_name': {'key': 'lastName', 'type': 'str'},
        'company_name': {'key': 'companyName', 'type': 'str'},
        'address_line1': {'key': 'addressLine1', 'type': 'str'},
        'address_line2': {'key': 'addressLine2', 'type': 'str'},
        'address_line3': {'key': 'addressLine3', 'type': 'str'},
        'city': {'key': 'city', 'type': 'str'},
        'region': {'key': 'region', 'type': 'str'},
        'country': {'key': 'country', 'type': 'str'},
        'postal_code': {'key': 'postalCode', 'type': 'str'},
    }

    def __init__(self, *, first_name: str=None, last_name: str=None, company_name: str=None, address_line1: str=None, address_line2: str=None, address_line3: str=None, city: str=None, region: str=None, country: str=None, postal_code: str=None, **kwargs) -> None:
        super(Address, self).__init__(**kwargs)
        self.first_name = first_name
        self.last_name = last_name
        self.company_name = company_name
        self.address_line1 = address_line1
        self.address_line2 = address_line2
        self.address_line3 = address_line3
        self.city = city
        self.region = region
        self.country = country
        self.postal_code = postal_code
