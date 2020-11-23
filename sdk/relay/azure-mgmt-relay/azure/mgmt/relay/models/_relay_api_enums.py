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


class AccessRights(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    MANAGE = "Manage"
    SEND = "Send"
    LISTEN = "Listen"

class KeyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The access key to regenerate.
    """

    PRIMARY_KEY = "PrimaryKey"
    SECONDARY_KEY = "SecondaryKey"

class ProvisioningStateEnum(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    CREATED = "Created"
    SUCCEEDED = "Succeeded"
    DELETED = "Deleted"
    FAILED = "Failed"
    UPDATING = "Updating"
    UNKNOWN = "Unknown"

class Relaytype(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """WCF relay type.
    """

    NET_TCP = "NetTcp"
    HTTP = "Http"

class UnavailableReason(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the reason for the unavailability of the service.
    """

    NONE = "None"
    INVALID_NAME = "InvalidName"
    SUBSCRIPTION_IS_DISABLED = "SubscriptionIsDisabled"
    NAME_IN_USE = "NameInUse"
    NAME_IN_LOCKDOWN = "NameInLockdown"
    TOO_MANY_NAMESPACE_IN_CURRENT_SUBSCRIPTION = "TooManyNamespaceInCurrentSubscription"
