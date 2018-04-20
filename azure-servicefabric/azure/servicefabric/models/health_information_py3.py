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


class HealthInformation(Model):
    """Represents common health report information. It is included in all health
    reports sent to health store and in all health events returned by health
    queries.

    All required parameters must be populated in order to send to Azure.

    :param source_id: Required. The source name which identifies the
     client/watchdog/system component which generated the health information.
    :type source_id: str
    :param property: Required. The property of the health information. An
     entity can have health reports for different properties.
     The property is a string and not a fixed enumeration to allow the reporter
     flexibility to categorize the state condition that triggers the report.
     For example, a reporter with SourceId "LocalWatchdog" can monitor the
     state of the available disk on a node,
     so it can report "AvailableDisk" property on that node.
     The same reporter can monitor the node connectivity, so it can report a
     property "Connectivity" on the same node.
     In the health store, these reports are treated as separate health events
     for the specified node.
     Together with the SourceId, the property uniquely identifies the health
     information.
    :type property: str
    :param health_state: Required. The health state of a Service Fabric entity
     such as Cluster, Node, Application, Service, Partition, Replica etc.
     Possible values include: 'Invalid', 'Ok', 'Warning', 'Error', 'Unknown'
    :type health_state: str or ~azure.servicefabric.models.HealthState
    :param time_to_live_in_milli_seconds: The duration for which this health
     report is valid. This field uses ISO8601 format for specifying the
     duration.
     When clients report periodically, they should send reports with higher
     frequency than time to live.
     If clients report on transition, they can set the time to live to
     infinite.
     When time to live expires, the health event that contains the health
     information
     is either removed from health store, if RemoveWhenExpired is true, or
     evaluated at error, if RemoveWhenExpired false.
     If not specified, time to live defaults to infinite value.
    :type time_to_live_in_milli_seconds: timedelta
    :param description: The description of the health information. It
     represents free text used to add human readable information about the
     report.
     The maximum string length for the description is 4096 characters.
     If the provided string is longer, it will be automatically truncated.
     When truncated, the last characters of the description contain a marker
     "[Truncated]", and total string size is 4096 characters.
     The presence of the marker indicates to users that truncation occurred.
     Note that when truncated, the description has less than 4096 characters
     from the original string.
    :type description: str
    :param sequence_number: The sequence number for this health report as a
     numeric string.
     The report sequence number is used by the health store to detect stale
     reports.
     If not specified, a sequence number is auto-generated by the health client
     when a report is added.
    :type sequence_number: str
    :param remove_when_expired: Value that indicates whether the report is
     removed from health store when it expires.
     If set to true, the report is removed from the health store after it
     expires.
     If set to false, the report is treated as an error when expired. The value
     of this property is false by default.
     When clients report periodically, they should set RemoveWhenExpired false
     (default).
     This way, is the reporter has issues (eg. deadlock) and can't report, the
     entity is evaluated at error when the health report expires.
     This flags the entity as being in Error health state.
    :type remove_when_expired: bool
    """

    _validation = {
        'source_id': {'required': True},
        'property': {'required': True},
        'health_state': {'required': True},
    }

    _attribute_map = {
        'source_id': {'key': 'SourceId', 'type': 'str'},
        'property': {'key': 'Property', 'type': 'str'},
        'health_state': {'key': 'HealthState', 'type': 'str'},
        'time_to_live_in_milli_seconds': {'key': 'TimeToLiveInMilliSeconds', 'type': 'duration'},
        'description': {'key': 'Description', 'type': 'str'},
        'sequence_number': {'key': 'SequenceNumber', 'type': 'str'},
        'remove_when_expired': {'key': 'RemoveWhenExpired', 'type': 'bool'},
    }

    def __init__(self, *, source_id: str, property: str, health_state, time_to_live_in_milli_seconds=None, description: str=None, sequence_number: str=None, remove_when_expired: bool=None, **kwargs) -> None:
        super(HealthInformation, self).__init__(**kwargs)
        self.source_id = source_id
        self.property = property
        self.health_state = health_state
        self.time_to_live_in_milli_seconds = time_to_live_in_milli_seconds
        self.description = description
        self.sequence_number = sequence_number
        self.remove_when_expired = remove_when_expired
