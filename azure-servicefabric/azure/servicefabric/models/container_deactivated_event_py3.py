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


class ContainerDeactivatedEvent(ApplicationEvent):
    """Container Deactivated event.

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
    :param service_name: Required. Name of Service.
    :type service_name: str
    :param service_package_name: Required. Name of Service package.
    :type service_package_name: str
    :param service_package_activation_id: Required. Activation Id of Service
     package.
    :type service_package_activation_id: str
    :param is_exclusive: Required. Indicates IsExclusive flag.
    :type is_exclusive: bool
    :param code_package_name: Required. Name of Code package.
    :type code_package_name: str
    :param entry_point_type: Required. Type of EntryPoint.
    :type entry_point_type: str
    :param image_name: Required. Name of Container image.
    :type image_name: str
    :param container_name: Required. Name of Container.
    :type container_name: str
    :param host_id: Required. Host Id.
    :type host_id: str
    :param exit_code: Required. Exit code of process.
    :type exit_code: long
    :param unexpected_termination: Required. Indicates if termination is
     unexpected.
    :type unexpected_termination: bool
    :param start_time: Required. Start time of process.
    :type start_time: datetime
    """

    _validation = {
        'event_instance_id': {'required': True},
        'time_stamp': {'required': True},
        'kind': {'required': True},
        'application_id': {'required': True},
        'service_name': {'required': True},
        'service_package_name': {'required': True},
        'service_package_activation_id': {'required': True},
        'is_exclusive': {'required': True},
        'code_package_name': {'required': True},
        'entry_point_type': {'required': True},
        'image_name': {'required': True},
        'container_name': {'required': True},
        'host_id': {'required': True},
        'exit_code': {'required': True},
        'unexpected_termination': {'required': True},
        'start_time': {'required': True},
    }

    _attribute_map = {
        'event_instance_id': {'key': 'EventInstanceId', 'type': 'str'},
        'time_stamp': {'key': 'TimeStamp', 'type': 'iso-8601'},
        'has_correlated_events': {'key': 'HasCorrelatedEvents', 'type': 'bool'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'application_id': {'key': 'ApplicationId', 'type': 'str'},
        'service_name': {'key': 'ServiceName', 'type': 'str'},
        'service_package_name': {'key': 'ServicePackageName', 'type': 'str'},
        'service_package_activation_id': {'key': 'ServicePackageActivationId', 'type': 'str'},
        'is_exclusive': {'key': 'IsExclusive', 'type': 'bool'},
        'code_package_name': {'key': 'CodePackageName', 'type': 'str'},
        'entry_point_type': {'key': 'EntryPointType', 'type': 'str'},
        'image_name': {'key': 'ImageName', 'type': 'str'},
        'container_name': {'key': 'ContainerName', 'type': 'str'},
        'host_id': {'key': 'HostId', 'type': 'str'},
        'exit_code': {'key': 'ExitCode', 'type': 'long'},
        'unexpected_termination': {'key': 'UnexpectedTermination', 'type': 'bool'},
        'start_time': {'key': 'StartTime', 'type': 'iso-8601'},
    }

    def __init__(self, *, event_instance_id: str, time_stamp, application_id: str, service_name: str, service_package_name: str, service_package_activation_id: str, is_exclusive: bool, code_package_name: str, entry_point_type: str, image_name: str, container_name: str, host_id: str, exit_code: int, unexpected_termination: bool, start_time, has_correlated_events: bool=None, **kwargs) -> None:
        super(ContainerDeactivatedEvent, self).__init__(event_instance_id=event_instance_id, time_stamp=time_stamp, has_correlated_events=has_correlated_events, application_id=application_id, **kwargs)
        self.service_name = service_name
        self.service_package_name = service_package_name
        self.service_package_activation_id = service_package_activation_id
        self.is_exclusive = is_exclusive
        self.code_package_name = code_package_name
        self.entry_point_type = entry_point_type
        self.image_name = image_name
        self.container_name = container_name
        self.host_id = host_id
        self.exit_code = exit_code
        self.unexpected_termination = unexpected_termination
        self.start_time = start_time
        self.kind = 'ContainerDeactivated'
