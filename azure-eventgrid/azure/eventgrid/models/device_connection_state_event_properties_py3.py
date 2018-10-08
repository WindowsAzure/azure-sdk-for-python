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


class DeviceConnectionStateEventProperties(Model):
    """Schema of the Data property of an EventGridEvent for a device connection
    state event (DeviceConnected, DeviceDisconnected).

    :param device_id: The unique identifier of the device. This case-sensitive
     string can be up to 128 characters long, and supports ASCII 7-bit
     alphanumeric characters plus the following special characters: - : . + % _
     &#35; * ? ! ( ) , = @ ; $ '.
    :type device_id: str
    :param module_id: The unique identifier of the module. This case-sensitive
     string can be up to 128 characters long, and supports ASCII 7-bit
     alphanumeric characters plus the following special characters: - : . + % _
     &#35; * ? ! ( ) , = @ ; $ '.
    :type module_id: str
    :param hub_name: Name of the IoT Hub where the device was created or
     deleted.
    :type hub_name: str
    :param device_connection_state_event_info: Information about the device
     connection state event.
    :type device_connection_state_event_info:
     ~azure.eventgrid.models.DeviceConnectionStateEventInfo
    """

    _attribute_map = {
        'device_id': {'key': 'deviceId', 'type': 'str'},
        'module_id': {'key': 'moduleId', 'type': 'str'},
        'hub_name': {'key': 'hubName', 'type': 'str'},
        'device_connection_state_event_info': {'key': 'deviceConnectionStateEventInfo', 'type': 'DeviceConnectionStateEventInfo'},
    }

    def __init__(self, *, device_id: str=None, module_id: str=None, hub_name: str=None, device_connection_state_event_info=None, **kwargs) -> None:
        super(DeviceConnectionStateEventProperties, self).__init__(**kwargs)
        self.device_id = device_id
        self.module_id = module_id
        self.hub_name = hub_name
        self.device_connection_state_event_info = device_connection_state_event_info
