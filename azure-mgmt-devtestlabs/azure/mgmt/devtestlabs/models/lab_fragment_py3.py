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

from .update_resource_py3 import UpdateResource


class LabFragment(UpdateResource):
    """A lab.

    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :param lab_storage_type: Type of storage used by the lab. It can be either
     Premium or Standard. Default is Premium. Possible values include:
     'Standard', 'Premium'
    :type lab_storage_type: str or ~azure.mgmt.devtestlabs.models.StorageType
    :param mandatory_artifacts_resource_ids_linux: The ordered list of
     artifact resource IDs that should be applied on all Linux VM creations by
     default, prior to the artifacts specified by the user.
    :type mandatory_artifacts_resource_ids_linux: list[str]
    :param mandatory_artifacts_resource_ids_windows: The ordered list of
     artifact resource IDs that should be applied on all Windows VM creations
     by default, prior to the artifacts specified by the user.
    :type mandatory_artifacts_resource_ids_windows: list[str]
    :param premium_data_disks: The setting to enable usage of premium data
     disks.
     When its value is 'Enabled', creation of standard or premium data disks is
     allowed.
     When its value is 'Disabled', only creation of standard data disks is
     allowed. Possible values include: 'Disabled', 'Enabled'
    :type premium_data_disks: str or
     ~azure.mgmt.devtestlabs.models.PremiumDataDisk
    :param environment_permission: The access rights to be granted to the user
     when provisioning an environment. Possible values include: 'Reader',
     'Contributor'
    :type environment_permission: str or
     ~azure.mgmt.devtestlabs.models.EnvironmentPermission
    :param announcement: The properties of any lab announcement associated
     with this lab
    :type announcement:
     ~azure.mgmt.devtestlabs.models.LabAnnouncementPropertiesFragment
    :param support: The properties of any lab support message associated with
     this lab
    :type support: ~azure.mgmt.devtestlabs.models.LabSupportPropertiesFragment
    :param extended_properties: Extended properties of the lab used for
     experimental features
    :type extended_properties: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'lab_storage_type': {'key': 'properties.labStorageType', 'type': 'str'},
        'mandatory_artifacts_resource_ids_linux': {'key': 'properties.mandatoryArtifactsResourceIdsLinux', 'type': '[str]'},
        'mandatory_artifacts_resource_ids_windows': {'key': 'properties.mandatoryArtifactsResourceIdsWindows', 'type': '[str]'},
        'premium_data_disks': {'key': 'properties.premiumDataDisks', 'type': 'str'},
        'environment_permission': {'key': 'properties.environmentPermission', 'type': 'str'},
        'announcement': {'key': 'properties.announcement', 'type': 'LabAnnouncementPropertiesFragment'},
        'support': {'key': 'properties.support', 'type': 'LabSupportPropertiesFragment'},
        'extended_properties': {'key': 'properties.extendedProperties', 'type': '{str}'},
    }

    def __init__(self, *, tags=None, lab_storage_type=None, mandatory_artifacts_resource_ids_linux=None, mandatory_artifacts_resource_ids_windows=None, premium_data_disks=None, environment_permission=None, announcement=None, support=None, extended_properties=None, **kwargs) -> None:
        super(LabFragment, self).__init__(tags=tags, **kwargs)
        self.lab_storage_type = lab_storage_type
        self.mandatory_artifacts_resource_ids_linux = mandatory_artifacts_resource_ids_linux
        self.mandatory_artifacts_resource_ids_windows = mandatory_artifacts_resource_ids_windows
        self.premium_data_disks = premium_data_disks
        self.environment_permission = environment_permission
        self.announcement = announcement
        self.support = support
        self.extended_properties = extended_properties
