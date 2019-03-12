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

from .chaos_event_py3 import ChaosEvent


class StartedChaosEvent(ChaosEvent):
    """Describes a Chaos event that gets generated when Chaos is started.

    All required parameters must be populated in order to send to Azure.

    :param time_stamp_utc: Required. The UTC timestamp when this Chaos event
     was generated.
    :type time_stamp_utc: datetime
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param chaos_parameters: Defines all the parameters to configure a Chaos
     run.
    :type chaos_parameters: ~azure.servicefabric.models.ChaosParameters
    """

    _validation = {
        'time_stamp_utc': {'required': True},
        'kind': {'required': True},
    }

    _attribute_map = {
        'time_stamp_utc': {'key': 'TimeStampUtc', 'type': 'iso-8601'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'chaos_parameters': {'key': 'ChaosParameters', 'type': 'ChaosParameters'},
    }

    def __init__(self, *, time_stamp_utc, chaos_parameters=None, **kwargs) -> None:
        super(StartedChaosEvent, self).__init__(time_stamp_utc=time_stamp_utc, **kwargs)
        self.chaos_parameters = chaos_parameters
        self.kind = 'Started'
