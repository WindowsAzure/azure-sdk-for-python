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

from .service_event import ServiceEvent


class ServiceDeletedEvent(ServiceEvent):
    """Service Deleted event.

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
    :param service_id: Required. The identity of the service. This ID is an
     encoded representation of the service name. This is used in the REST APIs
     to identify the service resource.
     Starting in version 6.0, hierarchical names are delimited with the "\\~"
     character. For example, if the service name is "fabric:/myapp/app1/svc1",
     the service identity would be "myapp~app1\\~svc1" in 6.0+ and
     "myapp/app1/svc1" in previous versions.
    :type service_id: str
    :param service_type_name: Required. Service type name.
    :type service_type_name: str
    :param application_name: Required. Application name.
    :type application_name: str
    :param application_type_name: Required. Application type name.
    :type application_type_name: str
    :param service_instance: Required. Id of Service instance.
    :type service_instance: long
    :param is_stateful: Required. Indicates if Service is stateful.
    :type is_stateful: bool
    :param partition_count: Required. Number of partitions.
    :type partition_count: int
    :param target_replica_set_size: Required. Size of target replicas set.
    :type target_replica_set_size: int
    :param min_replica_set_size: Required. Minimum size of replicas set.
    :type min_replica_set_size: int
    :param service_package_version: Required. Version of Service package.
    :type service_package_version: str
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'service_id': {'required': True},
        'service_type_name': {'required': True},
        'application_name': {'required': True},
        'application_type_name': {'required': True},
        'service_instance': {'required': True},
        'is_stateful': {'required': True},
        'partition_count': {'required': True},
        'target_replica_set_size': {'required': True},
        'min_replica_set_size': {'required': True},
        'service_package_version': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'category': {'key': 'Category', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'service_id': {'key': 'ServiceId', 'type': 'str'},
        'service_type_name': {'key': 'ServiceTypeName', 'type': 'str'},
        'application_name': {'key': 'ApplicationName', 'type': 'str'},
        'application_type_name': {'key': 'ApplicationTypeName', 'type': 'str'},
        'service_instance': {'key': 'ServiceInstance', 'type': 'long'},
        'is_stateful': {'key': 'IsStateful', 'type': 'bool'},
        'partition_count': {'key': 'PartitionCount', 'type': 'int'},
        'target_replica_set_size': {'key': 'TargetReplicaSetSize', 'type': 'int'},
        'min_replica_set_size': {'key': 'MinReplicaSetSize', 'type': 'int'},
        'service_package_version': {'key': 'ServicePackageVersion', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ServiceDeletedEvent, self).__init__(**kwargs)
        self.service_type_name = kwargs.get('service_type_name', None)
        self.application_name = kwargs.get('application_name', None)
        self.application_type_name = kwargs.get('application_type_name', None)
        self.service_instance = kwargs.get('service_instance', None)
        self.is_stateful = kwargs.get('is_stateful', None)
        self.partition_count = kwargs.get('partition_count', None)
        self.target_replica_set_size = kwargs.get('target_replica_set_size', None)
        self.min_replica_set_size = kwargs.get('min_replica_set_size', None)
        self.service_package_version = kwargs.get('service_package_version', None)
        self.kind = 'ServiceDeleted'
