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


class SyncGroupSchema(Model):
    """Properties of sync group schema.

    :param tables: List of tables in sync group schema.
    :type tables: list[~azure.mgmt.sql.models.SyncGroupSchemaTable]
    :param master_sync_member_name: Name of master sync member where the
     schema is from.
    :type master_sync_member_name: str
    """

    _attribute_map = {
        'tables': {'key': 'tables', 'type': '[SyncGroupSchemaTable]'},
        'master_sync_member_name': {'key': 'masterSyncMemberName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SyncGroupSchema, self).__init__(**kwargs)
        self.tables = kwargs.get('tables', None)
        self.master_sync_member_name = kwargs.get('master_sync_member_name', None)
