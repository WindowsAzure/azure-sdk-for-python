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


class IotHubCapacity(Model):
    """IoT Hub capacity information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar minimum: The minimum number of units.
    :vartype minimum: long
    :ivar maximum: The maximum number of units.
    :vartype maximum: long
    :ivar default: The default number of units.
    :vartype default: long
    :ivar scale_type: The type of the scaling enabled. Possible values
     include: 'Automatic', 'Manual', 'None'
    :vartype scale_type: str or :class:`IotHubScaleType
     <azure.mgmt.iothub.models.IotHubScaleType>`
    """

    _validation = {
        'minimum': {'readonly': True, 'maximum': 1, 'minimum': 1},
        'maximum': {'readonly': True},
        'default': {'readonly': True},
        'scale_type': {'readonly': True},
    }

    _attribute_map = {
        'minimum': {'key': 'minimum', 'type': 'long'},
        'maximum': {'key': 'maximum', 'type': 'long'},
        'default': {'key': 'default', 'type': 'long'},
        'scale_type': {'key': 'scaleType', 'type': 'IotHubScaleType'},
    }

    def __init__(self):
        self.minimum = None
        self.maximum = None
        self.default = None
        self.scale_type = None
