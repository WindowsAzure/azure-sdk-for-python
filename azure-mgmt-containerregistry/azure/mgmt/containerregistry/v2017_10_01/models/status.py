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


class Status(Model):
    """The status of an Azure resource at the time the operation was called.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar display_status: The short label for the status.
    :vartype display_status: str
    :ivar message: The detailed message for the status, including alerts and
     error messages.
    :vartype message: str
    :ivar timestamp: The timestamp when the status was changed to the current
     value.
    :vartype timestamp: datetime
    """

    _validation = {
        'display_status': {'readonly': True},
        'message': {'readonly': True},
        'timestamp': {'readonly': True},
    }

    _attribute_map = {
        'display_status': {'key': 'displayStatus', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
    }

    def __init__(self):
        super(Status, self).__init__()
        self.display_status = None
        self.message = None
        self.timestamp = None
