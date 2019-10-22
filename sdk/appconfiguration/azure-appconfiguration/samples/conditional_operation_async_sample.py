# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: conditional_operation_async_sample.py
DESCRIPTION:
    This sample demos conditional set/get/delete operations for app configuration
USAGE: python conditional_operation_async_sample.py
"""

import os
import sys
from azure.core import MatchConditions
from azure.core.exceptions import ResourceModifiedError
import asyncio
from azure.appconfiguration import ConfigurationSetting
from azure.appconfiguration.aio import AzureAppConfigurationClient
from util import print_configuration_setting

async def main():
    try:
        CONNECTION_STRING = os.environ['AZURE_APPCONFIG_CONNECTION_STRING']

    except KeyError:
        print("AZURE_APPCONFIG_CONNECTION_STRING must be set.")
        sys.exit(1)

    # Create app config client
    client = AzureAppConfigurationClient.from_connection_string(CONNECTION_STRING)

    # Unconditional set
    config_setting = ConfigurationSetting(
        key="MyKey",
        value="my value",
        content_type="my content type",
        tags={"my tag": "my tag value"}
    )
    await client.set_configuration_setting(config_setting)

    # Unconditional get
    first_get = await client.get_configuration_setting(key="MyKey")
    print_configuration_setting(first_get)

    # Conditional get, expect to return None
    second_get = await client.get_configuration_setting(
        key="MyKey",
        etag=first_get.etag,
        match_condition=MatchConditions.IfModified
    )
    print_configuration_setting(second_get)

    # Conditional set
    first_get.value = "new value"
    await client.set_configuration_setting(
        configuration_setting=first_get,
        match_condition=MatchConditions.IfNotModified
    )

    # Conditional set, expect to see error
    try:
        await client.set_configuration_setting(
            configuration_setting=first_get,
            match_condition=MatchConditions.IfNotModified
        )
    except ResourceModifiedError:
        pass

    await client.delete_configuration_setting(
        key="MyKey"
    )

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
