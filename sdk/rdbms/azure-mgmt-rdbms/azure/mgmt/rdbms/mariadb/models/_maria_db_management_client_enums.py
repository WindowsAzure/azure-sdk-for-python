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


class CreateMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The mode to create a new server.
    """

    DEFAULT = "Default"
    POINT_IN_TIME_RESTORE = "PointInTimeRestore"
    GEO_RESTORE = "GeoRestore"
    REPLICA = "Replica"

class GeoRedundantBackup(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Enable Geo-redundant or not for server backup.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class OperationOrigin(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The intended executor of the operation.
    """

    NOT_SPECIFIED = "NotSpecified"
    USER = "user"
    SYSTEM = "system"

class PrivateEndpointProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """State of the private endpoint connection.
    """

    APPROVING = "Approving"
    READY = "Ready"
    DROPPING = "Dropping"
    FAILED = "Failed"
    REJECTING = "Rejecting"

class PrivateLinkServiceConnectionStateActionsRequire(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The actions required for private link service connection.
    """

    NONE = "None"

class PrivateLinkServiceConnectionStateStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The private link service connection status.
    """

    APPROVED = "Approved"
    PENDING = "Pending"
    REJECTED = "Rejected"
    DISCONNECTED = "Disconnected"

class PublicNetworkAccessEnum(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Whether or not public network access is allowed for this server. Value is optional but if
    passed in, must be 'Enabled' or 'Disabled'
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class QueryPerformanceInsightResetDataResultState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Indicates result of the operation.
    """

    SUCCEEDED = "Succeeded"
    FAILED = "Failed"

class SecurityAlertPolicyName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    DEFAULT = "Default"

class ServerSecurityAlertPolicyState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the state of the policy, whether it is enabled or disabled.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class ServerState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """A state of a server that is visible to user.
    """

    READY = "Ready"
    DROPPING = "Dropping"
    DISABLED = "Disabled"

class ServerVersion(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The version of a server.
    """

    FIVE6 = "5.6"
    FIVE7 = "5.7"

class SkuTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The tier of the particular SKU, e.g. Basic.
    """

    BASIC = "Basic"
    GENERAL_PURPOSE = "GeneralPurpose"
    MEMORY_OPTIMIZED = "MemoryOptimized"

class SslEnforcementEnum(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Enable ssl enforcement or not when connect to server.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class StorageAutogrow(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Enable Storage Auto Grow.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class VirtualNetworkRuleState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Virtual Network Rule State
    """

    INITIALIZING = "Initializing"
    IN_PROGRESS = "InProgress"
    READY = "Ready"
    DELETING = "Deleting"
    UNKNOWN = "Unknown"
