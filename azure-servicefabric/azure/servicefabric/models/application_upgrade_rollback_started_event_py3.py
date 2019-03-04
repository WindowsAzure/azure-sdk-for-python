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

from .application_event_py3 import ApplicationEvent


class ApplicationUpgradeRollbackStartedEvent(ApplicationEvent):
    """Application Upgrade Rollback Started event.

    All required parameters must be populated in order to send to Azure.

    :param event_instance_id: Required. The identifier for the FabricEvent
     instance.
    :type event_instance_id: str
    :param category: The category of event.
    :type category: str
    :param time_stamp: Required. The time event was logged.
    :type time_stamp: datetime
    :param has_correlated_events: Shows there is existing related events
     available.
    :type has_correlated_events: bool
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param application_id: Required. The identity of the application. This is
     an encoded representation of the application name. This is used in the
     REST APIs to identify the application resource.
     Starting in version 6.0, hierarchical names are delimited with the "\\~"
     character. For example, if the application name is "fabric:/myapp/app1",
     the application identity would be "myapp\\~app1" in 6.0+ and "myapp/app1"
     in previous versions.
    :type application_id: str
    :param application_type_name: Required. Application type name.
    :type application_type_name: str
    :param current_application_type_version: Required. Current Application
     type version.
    :type current_application_type_version: str
    :param application_type_version: Required. Target Application type
     version.
    :type application_type_version: str
    :param failure_reason: Required. Describes reason of failure.
    :type failure_reason: str
    :param overall_upgrade_elapsed_time_in_ms: Required. Overall upgrade time
     in milli-seconds.
    :type overall_upgrade_elapsed_time_in_ms: float
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'application_id': {'required': True},
        'application_type_name': {'required': True},
        'current_application_type_version': {'required': True},
        'application_type_version': {'required': True},
        'failure_reason': {'required': True},
        'overall_upgrade_elapsed_time_in_ms': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'category': {'key': 'Category', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'application_id': {'key': 'ApplicationId', 'type': 'str'},
        'application_type_name': {'key': 'ApplicationTypeName', 'type': 'str'},
        'current_application_type_version': {'key': 'CurrentApplicationTypeVersion', 'type': 'str'},
        'application_type_version': {'key': 'ApplicationTypeVersion', 'type': 'str'},
        'failure_reason': {'key': 'FailureReason', 'type': 'str'},
        'overall_upgrade_elapsed_time_in_ms': {'key': 'OverallUpgradeElapsedTimeInMs', 'type': 'float'},
    }

    def __init__(self, *, event_instance_id: str, time_stamp, application_id: str, application_type_name: str, current_application_type_version: str, application_type_version: str, failure_reason: str, overall_upgrade_elapsed_time_in_ms: float, category: str=None, has_correlated_events: bool=None, **kwargs) -> None:
        super(ApplicationUpgradeRollbackStartedEvent, self).__init__(event_instance_id=event_instance_id, category=category, time_stamp=time_stamp, has_correlated_events=has_correlated_events, application_id=application_id, **kwargs)
        self.application_type_name = application_type_name
        self.current_application_type_version = current_application_type_version
        self.application_type_version = application_type_version
        self.failure_reason = failure_reason
        self.overall_upgrade_elapsed_time_in_ms = overall_upgrade_elapsed_time_in_ms
        self.kind = 'ApplicationUpgradeRollbackStarted'
