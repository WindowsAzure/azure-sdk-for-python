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


class ACLAction(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Default action when no other rule matches
    """

    ALLOW = "Allow"
    DENY = "Deny"

class FeatureFlags(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """FeatureFlags is the supported features of Azure SignalR service.
    
    
    * ServiceMode: Flag for backend server for SignalR service. Values allowed: "Default": have
    your own backend server; "Serverless": your application doesn't have a backend server;
    "Classic": for backward compatibility. Support both Default and Serverless mode but not
    recommended; "PredefinedOnly": for future use.
    * EnableConnectivityLogs: "true"/"false", to enable/disable the connectivity log category
    respectively.
    """

    SERVICE_MODE = "ServiceMode"
    ENABLE_CONNECTIVITY_LOGS = "EnableConnectivityLogs"
    ENABLE_MESSAGING_LOGS = "EnableMessagingLogs"

class KeyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The keyType to regenerate. Must be either 'primary' or 'secondary'(case-insensitive).
    """

    PRIMARY = "Primary"
    SECONDARY = "Secondary"

class ManagedIdentityType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Represent the identity type: systemAssigned, userAssigned, None
    """

    NONE = "None"
    SYSTEM_ASSIGNED = "SystemAssigned"
    USER_ASSIGNED = "UserAssigned"

class PrivateLinkServiceConnectionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Indicates whether the connection has been Approved/Rejected/Removed by the owner of the
    service.
    """

    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    DISCONNECTED = "Disconnected"

class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Provisioning state of the resource.
    """

    UNKNOWN = "Unknown"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELED = "Canceled"
    RUNNING = "Running"
    CREATING = "Creating"
    UPDATING = "Updating"
    DELETING = "Deleting"
    MOVING = "Moving"

class ServiceKind(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The kind of the service - e.g. "SignalR", or "RawWebSockets" for
    "Microsoft.SignalRService/SignalR"
    """

    SIGNAL_R = "SignalR"
    RAW_WEB_SOCKETS = "RawWebSockets"

class SignalRRequestType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Allowed request types. The value can be one or more of: ClientConnection, ServerConnection,
    RESTAPI.
    """

    CLIENT_CONNECTION = "ClientConnection"
    SERVER_CONNECTION = "ServerConnection"
    RESTAPI = "RESTAPI"

class SignalRSkuTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Optional tier of this particular SKU. 'Standard' or 'Free'.
    
    ``Basic`` is deprecated, use ``Standard`` instead.
    """

    FREE = "Free"
    BASIC = "Basic"
    STANDARD = "Standard"
    PREMIUM = "Premium"

class UpstreamAuthType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gets or sets the type of auth. None or ManagedIdentity is supported now.
    """

    NONE = "None"
    MANAGED_IDENTITY = "ManagedIdentity"
