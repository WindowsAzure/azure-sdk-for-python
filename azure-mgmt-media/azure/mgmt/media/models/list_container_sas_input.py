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

from msrest.serialization import Model


class ListContainerSasInput(Model):
    """The parameters to the list SAS request.

    :param permissions: The permissions to set on the SAS URL. Possible values
     include: 'Read', 'ReadWrite', 'ReadWriteDelete'
    :type permissions: str or
     ~azure.mgmt.media.models.AssetContainerPermission
    :param expiry_time: The SAS URL expiration time.  This must be less than
     24 hours from the current time.
    :type expiry_time: datetime
    """

    _attribute_map = {
        'permissions': {'key': 'permissions', 'type': 'AssetContainerPermission'},
        'expiry_time': {'key': 'expiryTime', 'type': 'iso-8601'},
    }

    def __init__(self, **kwargs):
        super(ListContainerSasInput, self).__init__(**kwargs)
        self.permissions = kwargs.get('permissions', None)
        self.expiry_time = kwargs.get('expiry_time', None)
