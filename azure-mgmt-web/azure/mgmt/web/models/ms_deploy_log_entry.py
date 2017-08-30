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


class MSDeployLogEntry(Model):
    """MSDeploy log entry.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar time: Timestamp of log entry
    :vartype time: datetime
    :ivar type: Log entry type. Possible values include: 'Message', 'Warning',
     'Error'
    :vartype type: str or :class:`MSDeployLogEntryType
     <azure.mgmt.web.models.MSDeployLogEntryType>`
    :ivar message: Log entry message
    :vartype message: str
    """

    _validation = {
        'time': {'readonly': True},
        'type': {'readonly': True},
        'message': {'readonly': True},
    }

    _attribute_map = {
        'time': {'key': 'time', 'type': 'iso-8601'},
        'type': {'key': 'type', 'type': 'MSDeployLogEntryType'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self):
        self.time = None
        self.type = None
        self.message = None
