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

from .server_properties_for_create import ServerPropertiesForCreate


class ServerPropertiesForRestore(ServerPropertiesForCreate):
    """The properties used to create a new server by restoring from a backup.

    All required parameters must be populated in order to send to Azure.

    :param version: Server version. Possible values include: '9.5', '9.6',
     '10', '10.0', '10.2'
    :type version: str or ~azure.mgmt.rdbms.postgresql.models.ServerVersion
    :param ssl_enforcement: Enable ssl enforcement or not when connect to
     server. Possible values include: 'Enabled', 'Disabled'
    :type ssl_enforcement: str or
     ~azure.mgmt.rdbms.postgresql.models.SslEnforcementEnum
    :param storage_profile: Storage profile of a server.
    :type storage_profile: ~azure.mgmt.rdbms.postgresql.models.StorageProfile
    :param create_mode: Required. Constant filled by server.
    :type create_mode: str
    :param source_server_id: Required. The source server id to restore from.
    :type source_server_id: str
    :param restore_point_in_time: Required. Restore point creation time
     (ISO8601 format), specifying the time to restore from.
    :type restore_point_in_time: datetime
    """

    _validation = {
        'create_mode': {'required': True},
        'source_server_id': {'required': True},
        'restore_point_in_time': {'required': True},
    }

    _attribute_map = {
        'version': {'key': 'version', 'type': 'str'},
        'ssl_enforcement': {'key': 'sslEnforcement', 'type': 'SslEnforcementEnum'},
        'storage_profile': {'key': 'storageProfile', 'type': 'StorageProfile'},
        'create_mode': {'key': 'createMode', 'type': 'str'},
        'source_server_id': {'key': 'sourceServerId', 'type': 'str'},
        'restore_point_in_time': {'key': 'restorePointInTime', 'type': 'iso-8601'},
    }

    def __init__(self, **kwargs):
        super(ServerPropertiesForRestore, self).__init__(**kwargs)
        self.source_server_id = kwargs.get('source_server_id', None)
        self.restore_point_in_time = kwargs.get('restore_point_in_time', None)
        self.create_mode = 'PointInTimeRestore'
