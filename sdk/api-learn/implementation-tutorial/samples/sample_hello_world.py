# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

import os
from colorama import init, Style, Fore
init()

from azure.identity import DefaultAzureCredential
from azure.appconfiguration import AppConfigurationClient

def main():
    url = os.environ.get('LEARNAPPCONFIG_ENDPOINT')
    credential = DefaultAzureCredential()
    client = AppConfigurationClient(account_url=url, credential=credential)

    try:
        color_setting = client.get_configuration_setting(os.enviorn['LEARNAPPCONFIG_SETTING_COLOR_KEY'])
        color = color_setting.value.upper()
        text_setting = client.get_configuration_setting(os.environ['LEARNAPPCONFIG_SETTING_TEXT_KEY'])
        greeting = text_setting.value
    except:
        color = 'RED'
        greeting = 'Default greeting'

    color = getattr(Fore, color)
    print(f'{color}{greeting}{Style.RESET_ALL}')


if __name__ == "__main__":
    main()