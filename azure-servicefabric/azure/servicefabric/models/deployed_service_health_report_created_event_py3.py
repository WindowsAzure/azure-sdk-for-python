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


class DeployedServiceHealthReportCreatedEvent(ApplicationEvent):
    """Deployed Service Health Report Created event.

    All required parameters must be populated in order to send to Azure.

    :param event_instance_id: Required. The identifier for the FabricEvent
     instance.
    :type event_instance_id: str
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
    :param service_manifest_name: Required. Service manifest name.
    :type service_manifest_name: str
    :param service_package_instance_id: Required. Id of Service package
     instance.
    :type service_package_instance_id: long
    :param service_package_activation_id: Required. Id of Service package
     activation.
    :type service_package_activation_id: str
    :param node_name: Required. The name of a Service Fabric node.
    :type node_name: str
    :param source_id: Required. Id of report source.
    :type source_id: str
    :param property: Required. Describes the property.
    :type property: str
    :param health_state: Required. Describes the property health state.
    :type health_state: str
    :param ttl_timespan: Required. Time to live in milli-seconds.
    :type ttl_timespan: long
    :param sequence_number: Required. Sequence number of report.
    :type sequence_number: long
    :param description: Required. Description of report.
    :type description: str
    :param remove_when_expired: Required. Indicates the removal when it
     expires.
    :type remove_when_expired: bool
    :param source_utc_timestamp: Required. Source time.
    :type source_utc_timestamp: datetime
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'application_id': {'required': True},
        'service_manifest_name': {'required': True},
        'service_package_instance_id': {'required': True},
        'service_package_activation_id': {'required': True},
        'node_name': {'required': True},
        'source_id': {'required': True},
        'property': {'required': True},
        'health_state': {'required': True},
        'ttl_timespan': {'required': True},
        'sequence_number': {'required': True},
        'description': {'required': True},
        'remove_when_expired': {'required': True},
        'source_utc_timestamp': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'application_id': {'key': 'ApplicationId', 'type': 'str'},
        'service_manifest_name': {'key': 'ServiceManifestName', 'type': 'str'},
        'service_package_instance_id': {'key': 'ServicePackageInstanceId', 'type': 'long'},
        'service_package_activation_id': {'key': 'ServicePackageActivationId', 'type': 'str'},
        'node_name': {'key': 'NodeName', 'type': 'str'},
        'source_id': {'key': 'SourceId', 'type': 'str'},
        'property': {'key': 'Property', 'type': 'str'},
        'health_state': {'key': 'HealthState', 'type': 'str'},
        'ttl_timespan': {'key': 'TTLTimespan', 'type': 'long'},
        'sequence_number': {'key': 'SequenceNumber', 'type': 'long'},
        'description': {'key': 'Description', 'type': 'str'},
        'remove_when_expired': {'key': 'RemoveWhenExpired', 'type': 'bool'},
        'source_utc_timestamp': {'key': 'SourceUtcTimestamp', 'type': 'iso-8601'},
    }

    def __init__(self, *, event_instance_id: str, time_stamp, application_id: str, service_manifest_name: str, service_package_instance_id: int, service_package_activation_id: str, node_name: str, source_id: str, property: str, health_state: str, ttl_timespan: int, sequence_number: int, description: str, remove_when_expired: bool, source_utc_timestamp, has_correlated_events: bool=None, **kwargs) -> None:
        super(DeployedServiceHealthReportCreatedEvent, self).__init__(event_instance_id=event_instance_id, time_stamp=time_stamp, has_correlated_events=has_correlated_events, application_id=application_id, **kwargs)
        self.service_manifest_name = service_manifest_name
        self.service_package_instance_id = service_package_instance_id
        self.service_package_activation_id = service_package_activation_id
        self.node_name = node_name
        self.source_id = source_id
        self.property = property
        self.health_state = health_state
        self.ttl_timespan = ttl_timespan
        self.sequence_number = sequence_number
        self.description = description
        self.remove_when_expired = remove_when_expired
        self.source_utc_timestamp = source_utc_timestamp
        self.kind = 'DeployedServiceHealthReportCreated'
