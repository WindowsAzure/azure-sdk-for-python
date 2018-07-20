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

from .proxy_resource_py3 import ProxyResource


class LiveOutput(ProxyResource):
    """The Live Output.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param description: The description of the Live Output.
    :type description: str
    :param asset_name: Required. The asset name.
    :type asset_name: str
    :param archive_window_length: Required. ISO 8601 timespan duration of the
     archive window length. This is duration that customer want to retain the
     recorded content.
    :type archive_window_length: timedelta
    :param manifest_name: The manifest file name.
    :type manifest_name: str
    :param hls: The HLS configuration.
    :type hls: ~azure.mgmt.media.models.Hls
    :param output_snap_time: The output snapshot time.
    :type output_snap_time: long
    :ivar created: The exact time the Live Output was created.
    :vartype created: datetime
    :ivar last_modified: The exact time the Live Output was last modified.
    :vartype last_modified: datetime
    :ivar provisioning_state: The provisioning state of the Live Output.
    :vartype provisioning_state: str
    :ivar resource_state: The resource state of the Live Output. Possible
     values include: 'Creating', 'Running', 'Deleting'
    :vartype resource_state: str or
     ~azure.mgmt.media.models.LiveOutputResourceState
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'asset_name': {'required': True},
        'archive_window_length': {'required': True},
        'created': {'readonly': True},
        'last_modified': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'resource_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'asset_name': {'key': 'properties.assetName', 'type': 'str'},
        'archive_window_length': {'key': 'properties.archiveWindowLength', 'type': 'duration'},
        'manifest_name': {'key': 'properties.manifestName', 'type': 'str'},
        'hls': {'key': 'properties.hls', 'type': 'Hls'},
        'output_snap_time': {'key': 'properties.outputSnapTime', 'type': 'long'},
        'created': {'key': 'properties.created', 'type': 'iso-8601'},
        'last_modified': {'key': 'properties.lastModified', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'resource_state': {'key': 'properties.resourceState', 'type': 'LiveOutputResourceState'},
    }

    def __init__(self, *, asset_name: str, archive_window_length, description: str=None, manifest_name: str=None, hls=None, output_snap_time: int=None, **kwargs) -> None:
        super(LiveOutput, self).__init__(**kwargs)
        self.description = description
        self.asset_name = asset_name
        self.archive_window_length = archive_window_length
        self.manifest_name = manifest_name
        self.hls = hls
        self.output_snap_time = output_snap_time
        self.created = None
        self.last_modified = None
        self.provisioning_state = None
        self.resource_state = None
