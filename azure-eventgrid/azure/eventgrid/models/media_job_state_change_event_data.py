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

from .event_grid_event_data import EventGridEventData


class MediaJobStateChangeEventData(EventGridEventData):
    """Schema of the Data property of an EventGridEvent for a
    Microsoft.Media.JobStateChange event.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar previous_state: The previous state of the Job. Possible values
     include: 'Canceled', 'Canceling', 'Error', 'Finished', 'Processing',
     'Queued', 'Scheduled'
    :vartype previous_state: str or ~azure.eventgrid.models.JobState
    :ivar state: The new state of the Job. Possible values include:
     'Canceled', 'Canceling', 'Error', 'Finished', 'Processing', 'Queued',
     'Scheduled'
    :vartype state: str or ~azure.eventgrid.models.JobState
    """

    _validation = {
        'previous_state': {'readonly': True},
        'state': {'readonly': True},
    }

    _attribute_map = {
        'previous_state': {'key': 'previousState', 'type': 'JobState'},
        'state': {'key': 'state', 'type': 'JobState'},
    }

    def __init__(self, **kwargs):
        super(MediaJobStateChangeEventData, self).__init__(**kwargs)
        self.previous_state = None
        self.state = None
