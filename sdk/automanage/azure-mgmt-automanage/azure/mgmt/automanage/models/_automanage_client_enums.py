# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum

class ConfigurationProfile(str, Enum):
    """A value indicating configuration profile.
    """

    azure_virtual_machine_best_practices_dev_test = "Azure virtual machine best practices – Dev/Test"
    azure_virtual_machine_best_practices_production = "Azure virtual machine best practices – Production"

class EnableRealTimeProtection(str, Enum):
    """Enables or disables Real Time Protection
    """

    true = "True"
    false = "False"

class ProvisioningStatus(str, Enum):
    """The state of onboarding, which only appears in the response.
    """

    succeeded = "Succeeded"
    failed = "Failed"
    created = "Created"

class ResourceIdentityType(str, Enum):
    """The type of identity used for the Automanage account. Currently, the only supported type is
    'SystemAssigned', which implicitly creates an identity.
    """

    system_assigned = "SystemAssigned"
    none = "None"

class RunScheduledScan(str, Enum):
    """Enables or disables a periodic scan for antimalware
    """

    true = "True"
    false = "False"

class ScanType(str, Enum):
    """Type of scheduled scan
    """

    quick = "Quick"
    full = "Full"

class UpdateStatus(str, Enum):
    """The state of compliance, which only appears in the response.
    """

    succeeded = "Succeeded"
    failed = "Failed"
    created = "Created"
