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


class PricingTier(str, Enum):

    free = "Free"  #: Get free Azure security center experience with basic security features
    standard = "Standard"  #: Get the standard Azure security center experience with advanced security features


class ReportedSeverity(str, Enum):

    informational = "Informational"
    low = "Low"
    medium = "Medium"
    high = "High"


class SettingKind(str, Enum):

    data_export_setting = "DataExportSetting"
    alert_suppression_setting = "AlertSuppressionSetting"


class SecurityFamily(str, Enum):

    waf = "Waf"
    ngfw = "Ngfw"
    saas_waf = "SaasWaf"
    va = "Va"


class AadConnectivityState(str, Enum):

    discovered = "Discovered"
    not_licensed = "NotLicensed"
    connected = "Connected"


class ExternalSecuritySolutionKind(str, Enum):

    cef = "CEF"
    ata = "ATA"
    aad = "AAD"


class Protocol(str, Enum):

    tcp = "TCP"
    udp = "UDP"
    all = "*"


class Status(str, Enum):

    revoked = "Revoked"
    initiated = "Initiated"


class StatusReason(str, Enum):

    expired = "Expired"
    user_requested = "UserRequested"
    newer_request_initiated = "NewerRequestInitiated"


class AutoProvision(str, Enum):

    on = "On"  #: Install missing security agent on VMs automatically
    off = "Off"  #: Do not install security agent on the VMs automatically


class AlertNotifications(str, Enum):

    on = "On"  #: Get notifications on new alerts
    off = "Off"  #: Don't get notifications on new alerts


class AlertsToAdmins(str, Enum):

    on = "On"  #: Send notification on new alerts to the subscription's admins
    off = "Off"  #: Don't send notification on new alerts to the subscription's admins


class State(str, Enum):

    passed = "Passed"  #: All supported regulatory compliance controls in the given standard have a passed state
    failed = "Failed"  #: At least one supported regulatory compliance control in the given standard has a state of failed
    skipped = "Skipped"  #: All supported regulatory compliance controls in the given standard have a state of skipped
    unsupported = "Unsupported"  #: No supported regulatory compliance data for the given standard


class ConnectionType(str, Enum):

    internal = "Internal"
    external = "External"
