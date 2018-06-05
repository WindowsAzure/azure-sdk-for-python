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

from .chaos_event import ChaosEvent


class ExecutingFaultsChaosEvent(ChaosEvent):
    """Describes a Chaos event that gets generated when Chaos has decided on the
    faults for an iteration. This Chaos event contains the details of the
    faults as a list of strings.

    All required parameters must be populated in order to send to Azure.

    :param time_stamp_utc: Required. The UTC timestamp when this Chaos event
     was generated.
    :type time_stamp_utc: datetime
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param faults: List of string description of the faults that Chaos decided
     to execute in an iteration.
    :type faults: list[str]
    """

    _validation = {
        'time_stamp_utc': {'required': True},
        'kind': {'required': True},
    }

    _attribute_map = {
        'time_stamp_utc': {'key': 'TimeStampUtc', 'type': 'iso-8601'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'faults': {'key': 'Faults', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ExecutingFaultsChaosEvent, self).__init__(**kwargs)
        self.faults = kwargs.get('faults', None)
        self.kind = 'ExecutingFaults'
