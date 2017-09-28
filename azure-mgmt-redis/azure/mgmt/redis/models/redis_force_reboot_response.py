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


class RedisForceRebootResponse(Model):
    """Response to force reboot for Redis cache.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar message: Status message
    :vartype message: str
    """

    _validation = {
        'message': {'readonly': True},
    }

    _attribute_map = {
        'message': {'key': 'Message', 'type': 'str'},
    }

    def __init__(self):
        self.message = None
