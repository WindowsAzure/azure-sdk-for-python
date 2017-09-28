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


class AzureTableStorageApplicationLogsConfig(Model):
    """Application logs to Azure table storage configuration.

    :param level: Log level. Possible values include: 'Off', 'Verbose',
     'Information', 'Warning', 'Error'
    :type level: str or :class:`LogLevel <azure.mgmt.web.models.LogLevel>`
    :param sas_url: SAS URL to an Azure table with add/query/delete
     permissions.
    :type sas_url: str
    """

    _validation = {
        'sas_url': {'required': True},
    }

    _attribute_map = {
        'level': {'key': 'level', 'type': 'LogLevel'},
        'sas_url': {'key': 'sasUrl', 'type': 'str'},
    }

    def __init__(self, sas_url, level=None):
        self.level = level
        self.sas_url = sas_url
