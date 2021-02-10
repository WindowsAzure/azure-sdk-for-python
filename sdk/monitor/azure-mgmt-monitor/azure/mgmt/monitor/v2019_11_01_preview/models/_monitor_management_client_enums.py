# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class KnownDataCollectionRuleAssociationProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The resource provisioning state.
    """

    CREATING = "Creating"
    UPDATING = "Updating"
    DELETING = "Deleting"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"

class KnownDataCollectionRuleProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The resource provisioning state.
    """

    CREATING = "Creating"
    UPDATING = "Updating"
    DELETING = "Deleting"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"

class KnownDataFlowStreams(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    MICROSOFT_ANTI_MALWARE_STATUS = "Microsoft-AntiMalwareStatus"
    MICROSOFT_AUDITD = "Microsoft-Auditd"
    MICROSOFT_CISCOASA = "Microsoft-CISCOASA"
    MICROSOFT_COMMON_SECURITY_LOG = "Microsoft-CommonSecurityLog"
    MICROSOFT_COMPUTER_GROUP = "Microsoft-ComputerGroup"
    MICROSOFT_EVENT = "Microsoft-Event"
    MICROSOFT_FIREWALL_LOG = "Microsoft-FirewallLog"
    MICROSOFT_HEALTH_STATE_CHANGE = "Microsoft-HealthStateChange"
    MICROSOFT_HEARTBEAT = "Microsoft-Heartbeat"
    MICROSOFT_INSIGHTS_METRICS = "Microsoft-InsightsMetrics"
    MICROSOFT_OPERATION_LOG = "Microsoft-OperationLog"
    MICROSOFT_PERF = "Microsoft-Perf"
    MICROSOFT_PROCESS_INVESTIGATOR = "Microsoft-ProcessInvestigator"
    MICROSOFT_PROTECTION_STATUS = "Microsoft-ProtectionStatus"
    MICROSOFT_ROME_DETECTION_EVENT = "Microsoft-RomeDetectionEvent"
    MICROSOFT_SECURITY_BASELINE = "Microsoft-SecurityBaseline"
    MICROSOFT_SECURITY_BASELINE_SUMMARY = "Microsoft-SecurityBaselineSummary"
    MICROSOFT_SECURITY_EVENT = "Microsoft-SecurityEvent"
    MICROSOFT_SYSLOG = "Microsoft-Syslog"
    MICROSOFT_WINDOWS_EVENT = "Microsoft-WindowsEvent"

class KnownExtensionDataSourceStreams(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    MICROSOFT_ANTI_MALWARE_STATUS = "Microsoft-AntiMalwareStatus"
    MICROSOFT_AUDITD = "Microsoft-Auditd"
    MICROSOFT_CISCOASA = "Microsoft-CISCOASA"
    MICROSOFT_COMMON_SECURITY_LOG = "Microsoft-CommonSecurityLog"
    MICROSOFT_COMPUTER_GROUP = "Microsoft-ComputerGroup"
    MICROSOFT_EVENT = "Microsoft-Event"
    MICROSOFT_FIREWALL_LOG = "Microsoft-FirewallLog"
    MICROSOFT_HEALTH_STATE_CHANGE = "Microsoft-HealthStateChange"
    MICROSOFT_HEARTBEAT = "Microsoft-Heartbeat"
    MICROSOFT_INSIGHTS_METRICS = "Microsoft-InsightsMetrics"
    MICROSOFT_OPERATION_LOG = "Microsoft-OperationLog"
    MICROSOFT_PERF = "Microsoft-Perf"
    MICROSOFT_PROCESS_INVESTIGATOR = "Microsoft-ProcessInvestigator"
    MICROSOFT_PROTECTION_STATUS = "Microsoft-ProtectionStatus"
    MICROSOFT_ROME_DETECTION_EVENT = "Microsoft-RomeDetectionEvent"
    MICROSOFT_SECURITY_BASELINE = "Microsoft-SecurityBaseline"
    MICROSOFT_SECURITY_BASELINE_SUMMARY = "Microsoft-SecurityBaselineSummary"
    MICROSOFT_SECURITY_EVENT = "Microsoft-SecurityEvent"
    MICROSOFT_SYSLOG = "Microsoft-Syslog"
    MICROSOFT_WINDOWS_EVENT = "Microsoft-WindowsEvent"

class KnownPerfCounterDataSourceScheduledTransferPeriod(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The interval between data uploads (scheduled transfers), rounded up to the nearest minute.
    """

    PT1_M = "PT1M"
    PT5_M = "PT5M"
    PT15_M = "PT15M"
    PT30_M = "PT30M"
    PT60_M = "PT60M"

class KnownPerfCounterDataSourceStreams(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    MICROSOFT_PERF = "Microsoft-Perf"
    MICROSOFT_INSIGHTS_METRICS = "Microsoft-InsightsMetrics"

class KnownSyslogDataSourceFacilityNames(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    AUTH = "auth"
    AUTHPRIV = "authpriv"
    CRON = "cron"
    DAEMON = "daemon"
    KERN = "kern"
    LPR = "lpr"
    MAIL = "mail"
    MARK = "mark"
    NEWS = "news"
    SYSLOG = "syslog"
    USER = "user"
    UUCP = "UUCP"
    LOCAL0 = "local0"
    LOCAL1 = "local1"
    LOCAL2 = "local2"
    LOCAL3 = "local3"
    LOCAL4 = "local4"
    LOCAL5 = "local5"
    LOCAL6 = "local6"
    LOCAL7 = "local7"

class KnownSyslogDataSourceLogLevels(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEBUG = "Debug"
    INFO = "Info"
    NOTICE = "Notice"
    WARNING = "Warning"
    ERROR = "Error"
    CRITICAL = "Critical"
    ALERT = "Alert"
    EMERGENCY = "Emergency"

class KnownSyslogDataSourceStreams(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    MICROSOFT_SYSLOG = "Microsoft-Syslog"

class KnownWindowsEventLogDataSourceScheduledTransferPeriod(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The interval between data uploads (scheduled transfers), rounded up to the nearest minute.
    """

    PT1_M = "PT1M"
    PT5_M = "PT5M"
    PT15_M = "PT15M"
    PT30_M = "PT30M"
    PT60_M = "PT60M"

class KnownWindowsEventLogDataSourceStreams(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    MICROSOFT_WINDOWS_EVENT = "Microsoft-WindowsEvent"
    MICROSOFT_EVENT = "Microsoft-Event"
