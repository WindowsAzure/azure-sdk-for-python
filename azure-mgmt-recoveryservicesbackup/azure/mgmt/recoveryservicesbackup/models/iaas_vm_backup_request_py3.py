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

from .backup_request_py3 import BackupRequest


class IaasVMBackupRequest(BackupRequest):
    """IaaS VM workload-specific backup request.

    All required parameters must be populated in order to send to Azure.

    :param object_type: Required. Constant filled by server.
    :type object_type: str
    :param recovery_point_expiry_time_in_utc: Backup copy will expire after
     the time specified (UTC).
    :type recovery_point_expiry_time_in_utc: datetime
    """

    _validation = {
        'object_type': {'required': True},
    }

    _attribute_map = {
        'object_type': {'key': 'objectType', 'type': 'str'},
        'recovery_point_expiry_time_in_utc': {'key': 'recoveryPointExpiryTimeInUTC', 'type': 'iso-8601'},
    }

    def __init__(self, *, recovery_point_expiry_time_in_utc=None, **kwargs) -> None:
        super(IaasVMBackupRequest, self).__init__(**kwargs)
        self.recovery_point_expiry_time_in_utc = recovery_point_expiry_time_in_utc
        self.object_type = 'IaasVMBackupRequest'
