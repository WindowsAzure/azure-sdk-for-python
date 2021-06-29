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


class ActionsRequired(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Any action that is required beyond basic workflow (approve/ reject/ disconnect)
    """

    NONE = "None"
    RECREATE = "Recreate"

class ConfigurationResourceType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The resource type to check for name availability.
    """

    MICROSOFT_APP_CONFIGURATION_CONFIGURATION_STORES = "Microsoft.AppConfiguration/configurationStores"

class ConnectionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The private link service connection status.
    """

    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    DISCONNECTED = "Disconnected"

class CreatedByType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of identity that created the resource.
    """

    USER = "User"
    APPLICATION = "Application"
    MANAGED_IDENTITY = "ManagedIdentity"
    KEY = "Key"

class IdentityType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of managed identity used. The type 'SystemAssigned, UserAssigned' includes both an
    implicitly created identity and a set of user-assigned identities. The type 'None' will remove
    any identities.
    """

    NONE = "None"
    SYSTEM_ASSIGNED = "SystemAssigned"
    USER_ASSIGNED = "UserAssigned"
    SYSTEM_ASSIGNED_USER_ASSIGNED = "SystemAssigned, UserAssigned"

class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The provisioning state of the configuration store.
    """

    CREATING = "Creating"
    UPDATING = "Updating"
    DELETING = "Deleting"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELED = "Canceled"

class PublicNetworkAccess(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Control permission for data plane traffic coming from public networks while private endpoint is
    enabled.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"
