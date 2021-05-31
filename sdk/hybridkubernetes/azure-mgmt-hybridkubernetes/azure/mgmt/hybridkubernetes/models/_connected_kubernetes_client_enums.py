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


class ConnectivityStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Represents the connectivity status of the connected cluster.
    """

    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    OFFLINE = "Offline"
    EXPIRED = "Expired"

class CreatedByType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of identity that created the resource.
    """

    USER = "User"
    APPLICATION = "Application"
    MANAGED_IDENTITY = "ManagedIdentity"
    KEY = "Key"

class LastModifiedByType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of identity that last modified the resource.
    """

    USER = "User"
    APPLICATION = "Application"
    MANAGED_IDENTITY = "ManagedIdentity"
    KEY = "Key"

class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current deployment state of connectedClusters.
    """

    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELED = "Canceled"
    PROVISIONING = "Provisioning"
    UPDATING = "Updating"
    DELETING = "Deleting"
    ACCEPTED = "Accepted"

class ResourceIdentityType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of identity used for the connected cluster. The type 'SystemAssigned, includes a
    system created identity. The type 'None' means no identity is assigned to the connected
    cluster.
    """

    NONE = "None"
    SYSTEM_ASSIGNED = "SystemAssigned"
