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

from .update_resource import UpdateResource


class ImageUpdate(UpdateResource):
    """The source user image virtual hard disk. The virtual hard disk will be
    copied before being attached to the virtual machine. If SourceImage is
    provided, the destination virtual hard drive must not exist.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param tags: Resource tags
    :type tags: dict[str, str]
    :param source_virtual_machine: The source virtual machine from which Image
     is created.
    :type source_virtual_machine:
     ~azure.mgmt.compute.v2017_12_01.models.SubResource
    :param storage_profile: Specifies the storage settings for the virtual
     machine disks.
    :type storage_profile:
     ~azure.mgmt.compute.v2017_12_01.models.ImageStorageProfile
    :ivar provisioning_state: The provisioning state.
    :vartype provisioning_state: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'source_virtual_machine': {'key': 'properties.sourceVirtualMachine', 'type': 'SubResource'},
        'storage_profile': {'key': 'properties.storageProfile', 'type': 'ImageStorageProfile'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ImageUpdate, self).__init__(**kwargs)
        self.source_virtual_machine = kwargs.get('source_virtual_machine', None)
        self.storage_profile = kwargs.get('storage_profile', None)
        self.provisioning_state = None
