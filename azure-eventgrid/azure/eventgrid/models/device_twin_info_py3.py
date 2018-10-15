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


class DeviceTwinInfo(Model):
    """Information about the device twin, which is the cloud representation of
    application device metadata.

    :param authentication_type: Authentication type used for this device:
     either SAS, SelfSigned, or CertificateAuthority.
    :type authentication_type: str
    :param cloud_to_device_message_count: Count of cloud to device messages
     sent to this device.
    :type cloud_to_device_message_count: float
    :param connection_state: Whether the device is connected or disconnected.
    :type connection_state: str
    :param device_id: The unique identifier of the device twin.
    :type device_id: str
    :param etag: A piece of information that describes the content of the
     device twin. Each etag is guaranteed to be unique per device twin.
    :type etag: str
    :param last_activity_time: The ISO8601 timestamp of the last activity.
    :type last_activity_time: str
    :param properties: Properties JSON element.
    :type properties: ~azure.eventgrid.models.DeviceTwinInfoProperties
    :param status: Whether the device twin is enabled or disabled.
    :type status: str
    :param status_update_time: The ISO8601 timestamp of the last device twin
     status update.
    :type status_update_time: str
    :param version: An integer that is incremented by one each time the device
     twin is updated.
    :type version: float
    :param x509_thumbprint: The thumbprint is a unique value for the x509
     certificate, commonly used to find a particular certificate in a
     certificate store. The thumbprint is dynamically generated using the SHA1
     algorithm, and does not physically exist in the certificate.
    :type x509_thumbprint:
     ~azure.eventgrid.models.DeviceTwinInfoX509Thumbprint
    """

    _attribute_map = {
        'authentication_type': {'key': 'authenticationType', 'type': 'str'},
        'cloud_to_device_message_count': {'key': 'cloudToDeviceMessageCount', 'type': 'float'},
        'connection_state': {'key': 'connectionState', 'type': 'str'},
        'device_id': {'key': 'deviceId', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'last_activity_time': {'key': 'lastActivityTime', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'DeviceTwinInfoProperties'},
        'status': {'key': 'status', 'type': 'str'},
        'status_update_time': {'key': 'statusUpdateTime', 'type': 'str'},
        'version': {'key': 'version', 'type': 'float'},
        'x509_thumbprint': {'key': 'x509Thumbprint', 'type': 'DeviceTwinInfoX509Thumbprint'},
    }

    def __init__(self, *, authentication_type: str=None, cloud_to_device_message_count: float=None, connection_state: str=None, device_id: str=None, etag: str=None, last_activity_time: str=None, properties=None, status: str=None, status_update_time: str=None, version: float=None, x509_thumbprint=None, **kwargs) -> None:
        super(DeviceTwinInfo, self).__init__(**kwargs)
        self.authentication_type = authentication_type
        self.cloud_to_device_message_count = cloud_to_device_message_count
        self.connection_state = connection_state
        self.device_id = device_id
        self.etag = etag
        self.last_activity_time = last_activity_time
        self.properties = properties
        self.status = status
        self.status_update_time = status_update_time
        self.version = version
        self.x509_thumbprint = x509_thumbprint
