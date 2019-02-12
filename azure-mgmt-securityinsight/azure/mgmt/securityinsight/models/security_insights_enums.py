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

from enum import Enum


class AlertRuleKind(str, Enum):

    scheduled = "Scheduled"


class AlertSeverity(str, Enum):

    high = "High"  #: High severity
    medium = "Medium"  #: Medium severity
    low = "Low"  #: Low severity
    informational = "Informational"  #: Informational severity


class TriggerOperator(str, Enum):

    greater_than = "GreaterThan"
    less_than = "LessThan"
    equal = "Equal"
    not_equal = "NotEqual"


class CaseSeverity(str, Enum):

    critical = "Critical"  #: Critical severity
    high = "High"  #: High severity
    medium = "Medium"  #: Medium severity
    low = "Low"  #: Low severity
    informational = "Informational"  #: Informational severity


class Status(str, Enum):

    draft = "Draft"  #: Case that wasn't promoted yet to active
    open = "Open"  #: An active case which isn't handled currently
    in_progress = "InProgress"  #: An active case which is handled
    closed = "Closed"  #: A non active case


class CloseReason(str, Enum):

    resolved = "Resolved"  #: Case was resolved
    dismissed = "Dismissed"  #: Case was dismissed
    other = "Other"  #: Case was closed for another reason


class DataConnectorKind(str, Enum):

    azure_active_directory = "AzureActiveDirectory"
    azure_security_center = "AzureSecurityCenter"
    microsoft_cloud_app_security = "MicrosoftCloudAppSecurity"
    threat_intelligence = "ThreatIntelligence"
    office365 = "Office365"


class DataTypeState(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class EntityKind(str, Enum):

    account = "Account"  #: Entity represents account in the system.
    host = "Host"  #: Entity represents host in the system.
    file = "File"  #: Entity represents file in the system.


class OSFamily(str, Enum):

    linux = "Linux"  #: Host with Linux operartion system.
    windows = "Windows"  #: Host with Windows operartion system.
    android = "Android"  #: Host with Android operartion system.
    ios = "IOS"  #: Host with IOS operartion system.


class SettingKind(str, Enum):

    ueba_settings = "UebaSettings"
    toggle_settings = "ToggleSettings"


class StatusInMcas(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"
