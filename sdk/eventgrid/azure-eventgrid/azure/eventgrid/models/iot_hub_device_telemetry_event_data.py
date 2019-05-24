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

from .device_telemetry_event_properties import DeviceTelemetryEventProperties


class IotHubDeviceTelemetryEventData(DeviceTelemetryEventProperties):
    """Event data for Microsoft.Devices.DeviceTelemetry event.

    :param body: The content of the message from the device.
    :type body: object
    :param properties: Application properties are user-defined strings that
     can be added to the message. These fields are optional.
    :type properties: dict[str, str]
    :param system_properties: System properties help identify contents and
     source of the messages.
    :type system_properties: dict[str, str]
    """

    _attribute_map = {
        'body': {'key': 'body', 'type': 'object'},
        'properties': {'key': 'properties', 'type': '{str}'},
        'system_properties': {'key': 'systemProperties', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(IotHubDeviceTelemetryEventData, self).__init__(**kwargs)
