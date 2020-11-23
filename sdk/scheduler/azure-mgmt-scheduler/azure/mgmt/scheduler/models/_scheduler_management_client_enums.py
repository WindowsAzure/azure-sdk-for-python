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


class DayOfWeek(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    SUNDAY = "Sunday"
    MONDAY = "Monday"
    TUESDAY = "Tuesday"
    WEDNESDAY = "Wednesday"
    THURSDAY = "Thursday"
    FRIDAY = "Friday"
    SATURDAY = "Saturday"

class HttpAuthenticationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or sets the HTTP authentication type.
    """

    NOT_SPECIFIED = "NotSpecified"
    CLIENT_CERTIFICATE = "ClientCertificate"
    ACTIVE_DIRECTORY_O_AUTH = "ActiveDirectoryOAuth"
    BASIC = "Basic"

class JobActionType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or sets the job action type.
    """

    HTTP = "Http"
    HTTPS = "Https"
    STORAGE_QUEUE = "StorageQueue"
    SERVICE_BUS_QUEUE = "ServiceBusQueue"
    SERVICE_BUS_TOPIC = "ServiceBusTopic"

class JobCollectionState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or sets the state.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"
    SUSPENDED = "Suspended"
    DELETED = "Deleted"

class JobExecutionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the job execution status.
    """

    COMPLETED = "Completed"
    FAILED = "Failed"
    POSTPONED = "Postponed"

class JobHistoryActionName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets the job history action name.
    """

    MAIN_ACTION = "MainAction"
    ERROR_ACTION = "ErrorAction"

class JobScheduleDay(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or sets the day. Must be one of monday, tuesday, wednesday, thursday, friday, saturday,
    sunday.
    """

    MONDAY = "Monday"
    TUESDAY = "Tuesday"
    WEDNESDAY = "Wednesday"
    THURSDAY = "Thursday"
    FRIDAY = "Friday"
    SATURDAY = "Saturday"
    SUNDAY = "Sunday"

class JobState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or set the job state.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"
    FAULTED = "Faulted"
    COMPLETED = "Completed"

class RecurrenceFrequency(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or sets the frequency of recurrence (second, minute, hour, day, week, month).
    """

    MINUTE = "Minute"
    HOUR = "Hour"
    DAY = "Day"
    WEEK = "Week"
    MONTH = "Month"

class RetryType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or sets the retry strategy to be used.
    """

    NONE = "None"
    FIXED = "Fixed"

class ServiceBusAuthenticationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or sets the authentication type.
    """

    NOT_SPECIFIED = "NotSpecified"
    SHARED_ACCESS_KEY = "SharedAccessKey"

class ServiceBusTransportType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or sets the transport type.
    """

    NOT_SPECIFIED = "NotSpecified"
    NET_MESSAGING = "NetMessaging"
    AMQP = "AMQP"

class SkuDefinition(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or set the SKU.
    """

    STANDARD = "Standard"
    FREE = "Free"
    P10_PREMIUM = "P10Premium"
    P20_PREMIUM = "P20Premium"
