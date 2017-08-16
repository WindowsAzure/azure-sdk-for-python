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


class PacketCaptureParameters(Model):
    """Parameters that define the create packet capture operation.

    :param target: The ID of the targeted resource, only VM is currently
     supported.
    :type target: str
    :param bytes_to_capture_per_packet: Number of bytes captured per packet,
     the remaining bytes are truncated. Default value: 0 .
    :type bytes_to_capture_per_packet: int
    :param total_bytes_per_session: Maximum size of the capture output.
     Default value: 1073741824 .
    :type total_bytes_per_session: int
    :param time_limit_in_seconds: Maximum duration of the capture session in
     seconds. Default value: 18000 .
    :type time_limit_in_seconds: int
    :param storage_location:
    :type storage_location: :class:`PacketCaptureStorageLocation
     <azure.mgmt.network.v2017_03_01.models.PacketCaptureStorageLocation>`
    :param filters:
    :type filters: list of :class:`PacketCaptureFilter
     <azure.mgmt.network.v2017_03_01.models.PacketCaptureFilter>`
    """

    _validation = {
        'target': {'required': True},
        'storage_location': {'required': True},
    }

    _attribute_map = {
        'target': {'key': 'target', 'type': 'str'},
        'bytes_to_capture_per_packet': {'key': 'bytesToCapturePerPacket', 'type': 'int'},
        'total_bytes_per_session': {'key': 'totalBytesPerSession', 'type': 'int'},
        'time_limit_in_seconds': {'key': 'timeLimitInSeconds', 'type': 'int'},
        'storage_location': {'key': 'storageLocation', 'type': 'PacketCaptureStorageLocation'},
        'filters': {'key': 'filters', 'type': '[PacketCaptureFilter]'},
    }

    def __init__(self, target, storage_location, bytes_to_capture_per_packet=0, total_bytes_per_session=1073741824, time_limit_in_seconds=18000, filters=None):
        self.target = target
        self.bytes_to_capture_per_packet = bytes_to_capture_per_packet
        self.total_bytes_per_session = total_bytes_per_session
        self.time_limit_in_seconds = time_limit_in_seconds
        self.storage_location = storage_location
        self.filters = filters
