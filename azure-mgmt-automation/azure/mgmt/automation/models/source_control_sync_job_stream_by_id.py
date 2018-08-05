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


class SourceControlSyncJobStreamById(Model):
    """Definition of the source control sync job stream by id.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource id.
    :vartype id: str
    :param sync_job_stream_id: Gets the sync job stream id.
    :type sync_job_stream_id: str
    :param summary: Gets the summary of the sync job stream.
    :type summary: str
    :ivar time: Gets the time of the sync job stream.
    :vartype time: datetime
    :param stream_type: Gets the type of the sync job stream. Possible values
     include: 'Error', 'Output'
    :type stream_type: str or ~azure.mgmt.automation.models.StreamType
    :param stream_text: Gets the text of the sync job stream.
    :type stream_text: str
    :param value: Gets or sets the values of the job stream.
    :type value: dict[str, object]
    """

    _validation = {
        'id': {'readonly': True},
        'time': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'sync_job_stream_id': {'key': 'properties.syncJobStreamId', 'type': 'str'},
        'summary': {'key': 'properties.summary', 'type': 'str'},
        'time': {'key': 'properties.time', 'type': 'iso-8601'},
        'stream_type': {'key': 'properties.streamType', 'type': 'str'},
        'stream_text': {'key': 'properties.streamText', 'type': 'str'},
        'value': {'key': 'properties.value', 'type': '{object}'},
    }

    def __init__(self, sync_job_stream_id=None, summary=None, stream_type=None, stream_text=None, value=None):
        super(SourceControlSyncJobStreamById, self).__init__()
        self.id = None
        self.sync_job_stream_id = sync_job_stream_id
        self.summary = summary
        self.time = None
        self.stream_type = stream_type
        self.stream_text = stream_text
        self.value = value
