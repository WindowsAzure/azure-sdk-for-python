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

from .azure_appconfiguration_client import AzureAppConfigurationClient
from ._models import ConfigurationSetting
from ._version import VERSION
from ._azure_appconfiguration_error import ResourceReadOnlyError

__version__ = VERSION
__all__ = ["AzureAppConfigurationClient", "ConfigurationSetting", "ResourceReadOnlyError"]
