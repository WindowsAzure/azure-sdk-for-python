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

from .media_job_state_change_event_data_py3 import MediaJobStateChangeEventData


class MediaJobCancelingEventData(MediaJobStateChangeEventData):
    """Job canceling event data.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar previous_state: The previous state of the Job. Possible values
     include: 'Canceled', 'Canceling', 'Error', 'Finished', 'Processing',
     'Queued', 'Scheduled'
    :vartype previous_state: str or ~azure.eventgrid.models.MediaJobState
    :ivar state: The new state of the Job. Possible values include:
     'Canceled', 'Canceling', 'Error', 'Finished', 'Processing', 'Queued',
     'Scheduled'
    :vartype state: str or ~azure.eventgrid.models.MediaJobState
    :param correlation_data: Gets the Job correlation data.
    :type correlation_data: dict[str, str]
    """

    _validation = {
        'previous_state': {'readonly': True},
        'state': {'readonly': True},
    }

    _attribute_map = {
        'previous_state': {'key': 'previousState', 'type': 'MediaJobState'},
        'state': {'key': 'state', 'type': 'MediaJobState'},
        'correlation_data': {'key': 'correlationData', 'type': '{str}'},
    }

    def __init__(self, *, correlation_data=None, **kwargs) -> None:
        super(MediaJobCancelingEventData, self).__init__(correlation_data=correlation_data, **kwargs)
