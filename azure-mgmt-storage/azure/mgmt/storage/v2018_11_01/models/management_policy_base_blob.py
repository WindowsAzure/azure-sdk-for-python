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


class ManagementPolicyBaseBlob(Model):
    """Management policy action for base blob.

    :param tier_to_cool: The function to tier blobs to cool storage. Support
     blobs currently at Hot tier
    :type tier_to_cool:
     ~azure.mgmt.storage.v2018_11_01.models.DateAfterModification
    :param tier_to_archive: The function to tier blobs to archive storage.
     Support blobs currently at Hot or Cool tier
    :type tier_to_archive:
     ~azure.mgmt.storage.v2018_11_01.models.DateAfterModification
    :param delete: The function to delete the blob
    :type delete: ~azure.mgmt.storage.v2018_11_01.models.DateAfterModification
    """

    _attribute_map = {
        'tier_to_cool': {'key': 'tierToCool', 'type': 'DateAfterModification'},
        'tier_to_archive': {'key': 'tierToArchive', 'type': 'DateAfterModification'},
        'delete': {'key': 'delete', 'type': 'DateAfterModification'},
    }

    def __init__(self, **kwargs):
        super(ManagementPolicyBaseBlob, self).__init__(**kwargs)
        self.tier_to_cool = kwargs.get('tier_to_cool', None)
        self.tier_to_archive = kwargs.get('tier_to_archive', None)
        self.delete = kwargs.get('delete', None)
