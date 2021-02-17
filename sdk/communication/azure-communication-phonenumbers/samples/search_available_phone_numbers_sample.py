# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: search_available_phone_numbers_sample.py
DESCRIPTION:
    This sample demonstrates how to search for available numbers you can buy with the respective API.
USAGE:
    python search_available_phone_numbers_sample.py
    Set the environment variables with your own values before running the sample:
    1) AZURE_COMMUNICATION_SERVICE_CONNECTION_STRING - The endpoint of your Azure Communication Service
    2) AZURE_COMMUNICATION_SERVICE_AREA_CODE - The area code you want the number to be in
"""

import os
from azure.communication.phonenumbers import (
    PhoneNumbersClient,
    PhoneNumberType,
    PhoneNumberAssignmentType,
    PhoneNumberCapabilities,
    PhoneNumberCapabilityValue
)

connection_str = os.getenv('AZURE_COMMUNICATION_SERVICE_CONNECTION_STRING')
area_code = os.getenv('AZURE_COMMUNICATION_SERVICE_AREA_CODE')
phone_numbers_client = PhoneNumbersClient.from_connection_string(connection_str)

def search_available_phone_numbers():
    capabilities = PhoneNumberCapabilities(
        calling = PhoneNumberCapabilityValue.INBOUND,
        sms = PhoneNumberCapabilityValue.INBOUND_OUTBOUND
    )
    poller = phone_numbers_client.begin_search_available_phone_numbers(
        "US",
        PhoneNumberType.TOLL_FREE,
        PhoneNumberAssignmentType.APPLICATION,
        capabilities,
        area_code,
        1,
        polling = True
    )
    print('Acquired phone numbers:')
    print(poller.result)


if __name__ == '__main__':
    search_available_phone_numbers()