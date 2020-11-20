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


class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The provisioning state of the resource.
    """

    ACCEPTED = "Accepted"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"

class SpendingLimit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The subscription spending limit.
    """

    ON = "On"
    OFF = "Off"
    CURRENT_PERIOD_OFF = "CurrentPeriodOff"

class SubscriptionState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The subscription state. Possible values are Enabled, Warned, PastDue, Disabled, and Deleted.
    """

    ENABLED = "Enabled"
    WARNED = "Warned"
    PAST_DUE = "PastDue"
    DISABLED = "Disabled"
    DELETED = "Deleted"

class Workload(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The workload type of the subscription. It can be either Production or DevTest.
    """

    PRODUCTION = "Production"
    DEV_TEST = "DevTest"
