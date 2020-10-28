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


class AggregatedReplicationState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """This is the aggregated replication status based on all the regional replication status flags.
    """

    UNKNOWN = "Unknown"
    IN_PROGRESS = "InProgress"
    COMPLETED = "Completed"
    FAILED = "Failed"

class GalleryApplicationVersionPropertiesProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The provisioning state, which only appears in the response.
    """

    CREATING = "Creating"
    UPDATING = "Updating"
    FAILED = "Failed"
    SUCCEEDED = "Succeeded"
    DELETING = "Deleting"
    MIGRATING = "Migrating"

class GalleryImagePropertiesProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The provisioning state, which only appears in the response.
    """

    CREATING = "Creating"
    UPDATING = "Updating"
    FAILED = "Failed"
    SUCCEEDED = "Succeeded"
    DELETING = "Deleting"
    MIGRATING = "Migrating"

class GalleryImageVersionPropertiesProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The provisioning state, which only appears in the response.
    """

    CREATING = "Creating"
    UPDATING = "Updating"
    FAILED = "Failed"
    SUCCEEDED = "Succeeded"
    DELETING = "Deleting"
    MIGRATING = "Migrating"

class GalleryPropertiesProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The provisioning state, which only appears in the response.
    """

    CREATING = "Creating"
    UPDATING = "Updating"
    FAILED = "Failed"
    SUCCEEDED = "Succeeded"
    DELETING = "Deleting"
    MIGRATING = "Migrating"

class GallerySharingPermissionTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """This property allows you to specify the permission of sharing gallery. :code:`<br>`:code:`<br>`
    Possible values are: :code:`<br>`:code:`<br>` **Private** :code:`<br>`:code:`<br>` **Groups**
    """

    PRIVATE = "Private"
    GROUPS = "Groups"

class HostCaching(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The host caching of the disk. Valid values are 'None', 'ReadOnly', and 'ReadWrite'
    """

    NONE = "None"
    READ_ONLY = "ReadOnly"
    READ_WRITE = "ReadWrite"

class HyperVGeneration(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The hypervisor generation of the Virtual Machine. Applicable to OS disks only.
    """

    V1 = "V1"
    V2 = "V2"

class OperatingSystemStateTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """This property allows the user to specify whether the virtual machines created under this image
    are 'Generalized' or 'Specialized'.
    """

    GENERALIZED = "Generalized"
    SPECIALIZED = "Specialized"

class OperatingSystemTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """This property allows you to specify the supported type of the OS that application is built for.
    :code:`<br>`:code:`<br>` Possible values are: :code:`<br>`:code:`<br>` **Windows**
    :code:`<br>`:code:`<br>` **Linux**
    """

    WINDOWS = "Windows"
    LINUX = "Linux"

class ReplicationState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """This is the regional replication state.
    """

    UNKNOWN = "Unknown"
    REPLICATING = "Replicating"
    COMPLETED = "Completed"
    FAILED = "Failed"

class ReplicationStatusTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    REPLICATION_STATUS = "ReplicationStatus"

class SelectPermissions(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    PERMISSIONS = "Permissions"

class SharedToValues(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    TENANT = "tenant"

class SharingProfileGroupTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """This property allows you to specify the type of sharing group. :code:`<br>`:code:`<br>`
    Possible values are: :code:`<br>`:code:`<br>` **Subscriptions** :code:`<br>`:code:`<br>`
    **AADTenants**
    """

    SUBSCRIPTIONS = "Subscriptions"
    AAD_TENANTS = "AADTenants"

class SharingUpdateOperationTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """This property allows you to specify the operation type of gallery sharing update.
    :code:`<br>`:code:`<br>` Possible values are: :code:`<br>`:code:`<br>` **Add**
    :code:`<br>`:code:`<br>` **Remove** :code:`<br>`:code:`<br>` **Reset**
    """

    ADD = "Add"
    REMOVE = "Remove"
    RESET = "Reset"

class StorageAccountType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Specifies the storage account type to be used to store the image. This property is not
    updatable.
    """

    STANDARD_LRS = "Standard_LRS"
    STANDARD_ZRS = "Standard_ZRS"
    PREMIUM_LRS = "Premium_LRS"
