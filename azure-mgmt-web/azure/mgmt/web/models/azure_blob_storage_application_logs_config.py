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


class AzureBlobStorageApplicationLogsConfig(Model):
    """Application logs azure blob storage configuration.

    :param level: Log level. Possible values include: 'Off', 'Verbose',
     'Information', 'Warning', 'Error'
    :type level: str or :class:`LogLevel <azure.mgmt.web.models.LogLevel>`
    :param sas_url: SAS url to a azure blob container with
     read/write/list/delete permissions
    :type sas_url: str
    :param retention_in_days: Retention in days.
     Remove blobs older than X days.
     0 or lower means no retention.
    :type retention_in_days: int
    """ 

    _attribute_map = {
        'level': {'key': 'level', 'type': 'LogLevel'},
        'sas_url': {'key': 'sasUrl', 'type': 'str'},
        'retention_in_days': {'key': 'retentionInDays', 'type': 'int'},
    }

    def __init__(self, level=None, sas_url=None, retention_in_days=None):
        self.level = level
        self.sas_url = sas_url
        self.retention_in_days = retention_in_days
