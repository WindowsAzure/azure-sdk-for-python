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


class CsmSiteRecoveryEntity(Model):
    """Class containting details about site recovery operation.

    :param snapshot_time: Point in time in which the site recover should be
     attempted.
    :type snapshot_time: datetime
    :param recover_config: If true, then the website's configuration will be
     reverted to its state at SnapshotTime
    :type recover_config: bool
    :param site_name: [Optional] Destination web app name into which web app
     should be recovered. This is case when new web app should be created
     instead.
    :type site_name: str
    :param slot_name: [Optional] Destination web app slot name into which web
     app should be recovered
    :type slot_name: str
    """ 

    _attribute_map = {
        'snapshot_time': {'key': 'snapshotTime', 'type': 'iso-8601'},
        'recover_config': {'key': 'recoverConfig', 'type': 'bool'},
        'site_name': {'key': 'siteName', 'type': 'str'},
        'slot_name': {'key': 'slotName', 'type': 'str'},
    }

    def __init__(self, snapshot_time=None, recover_config=None, site_name=None, slot_name=None):
        self.snapshot_time = snapshot_time
        self.recover_config = recover_config
        self.site_name = site_name
        self.slot_name = slot_name
