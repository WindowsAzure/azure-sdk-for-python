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


class BackupSchedule(Model):
    """Description of a backup schedule. Describes how often should be the backup
    performed and what should be the retention policy.

    :param frequency_interval: How often should be the backup executed (e.g.
     for weekly backup, this should be set to 7 and FrequencyUnit should be set
     to Day)
    :type frequency_interval: int
    :param frequency_unit: How often should be the backup executed (e.g. for
     weekly backup, this should be set to Day and FrequencyInterval should be
     set to 7). Possible values include: 'Day', 'Hour'
    :type frequency_unit: str or :class:`FrequencyUnit
     <azure.mgmt.web.models.FrequencyUnit>`
    :param keep_at_least_one_backup: True if the retention policy should
     always keep at least one backup in the storage account, regardless how old
     it is; false otherwise.
    :type keep_at_least_one_backup: bool
    :param retention_period_in_days: After how many days backups should be
     deleted
    :type retention_period_in_days: int
    :param start_time: When the schedule should start working
    :type start_time: datetime
    :param last_execution_time: The last time when this schedule was triggered
    :type last_execution_time: datetime
    """

    _validation = {
        'frequency_unit': {'required': True},
    }

    _attribute_map = {
        'frequency_interval': {'key': 'frequencyInterval', 'type': 'int'},
        'frequency_unit': {'key': 'frequencyUnit', 'type': 'FrequencyUnit'},
        'keep_at_least_one_backup': {'key': 'keepAtLeastOneBackup', 'type': 'bool'},
        'retention_period_in_days': {'key': 'retentionPeriodInDays', 'type': 'int'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'last_execution_time': {'key': 'lastExecutionTime', 'type': 'iso-8601'},
    }

    def __init__(self, frequency_unit, frequency_interval=None, keep_at_least_one_backup=None, retention_period_in_days=None, start_time=None, last_execution_time=None):
        self.frequency_interval = frequency_interval
        self.frequency_unit = frequency_unit
        self.keep_at_least_one_backup = keep_at_least_one_backup
        self.retention_period_in_days = retention_period_in_days
        self.start_time = start_time
        self.last_execution_time = last_execution_time
