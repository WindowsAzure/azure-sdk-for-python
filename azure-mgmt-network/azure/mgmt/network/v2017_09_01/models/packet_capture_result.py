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


class PacketCaptureResult(Model):
    """Information about packet capture session.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar name: Name of the packet capture session.
    :vartype name: str
    :ivar id: ID of the packet capture operation.
    :vartype id: str
    :param etag:  Default value: "A unique read-only string that changes
     whenever the resource is updated." .
    :type etag: str
    :param target: Required. The ID of the targeted resource, only VM is
     currently supported.
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
    :param storage_location: Required.
    :type storage_location:
     ~azure.mgmt.network.v2017_09_01.models.PacketCaptureStorageLocation
    :param filters:
    :type filters:
     list[~azure.mgmt.network.v2017_09_01.models.PacketCaptureFilter]
    :param provisioning_state: The provisioning state of the packet capture
     session. Possible values include: 'Succeeded', 'Updating', 'Deleting',
     'Failed'
    :type provisioning_state: str or
     ~azure.mgmt.network.v2017_09_01.models.ProvisioningState
    """

    _validation = {
        'name': {'readonly': True},
        'id': {'readonly': True},
        'target': {'required': True},
        'storage_location': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'target': {'key': 'properties.target', 'type': 'str'},
        'bytes_to_capture_per_packet': {'key': 'properties.bytesToCapturePerPacket', 'type': 'int'},
        'total_bytes_per_session': {'key': 'properties.totalBytesPerSession', 'type': 'int'},
        'time_limit_in_seconds': {'key': 'properties.timeLimitInSeconds', 'type': 'int'},
        'storage_location': {'key': 'properties.storageLocation', 'type': 'PacketCaptureStorageLocation'},
        'filters': {'key': 'properties.filters', 'type': '[PacketCaptureFilter]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PacketCaptureResult, self).__init__(**kwargs)
        self.name = None
        self.id = None
        self.etag = kwargs.get('etag', "A unique read-only string that changes whenever the resource is updated.")
        self.target = kwargs.get('target', None)
        self.bytes_to_capture_per_packet = kwargs.get('bytes_to_capture_per_packet', 0)
        self.total_bytes_per_session = kwargs.get('total_bytes_per_session', 1073741824)
        self.time_limit_in_seconds = kwargs.get('time_limit_in_seconds', 18000)
        self.storage_location = kwargs.get('storage_location', None)
        self.filters = kwargs.get('filters', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
