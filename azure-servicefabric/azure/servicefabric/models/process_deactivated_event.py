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

from .application_event import ApplicationEvent


class ProcessDeactivatedEvent(ApplicationEvent):
    """Process Deactivated event.

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
    :param exe_name: Required. Name of executable.
    :type exe_name: str
    :param process_id: Required. Process Id.
    :type process_id: long
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
        'exe_name': {'required': True},
        'process_id': {'required': True},
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
        'exe_name': {'key': 'ExeName', 'type': 'str'},
        'process_id': {'key': 'ProcessId', 'type': 'long'},
        'host_id': {'key': 'HostId', 'type': 'str'},
        'exit_code': {'key': 'ExitCode', 'type': 'long'},
        'unexpected_termination': {'key': 'UnexpectedTermination', 'type': 'bool'},
        'start_time': {'key': 'StartTime', 'type': 'iso-8601'},
    }

    def __init__(self, **kwargs):
        super(ProcessDeactivatedEvent, self).__init__(**kwargs)
        self.service_name = kwargs.get('service_name', None)
        self.service_package_name = kwargs.get('service_package_name', None)
        self.service_package_activation_id = kwargs.get('service_package_activation_id', None)
        self.is_exclusive = kwargs.get('is_exclusive', None)
        self.code_package_name = kwargs.get('code_package_name', None)
        self.entry_point_type = kwargs.get('entry_point_type', None)
        self.exe_name = kwargs.get('exe_name', None)
        self.process_id = kwargs.get('process_id', None)
        self.host_id = kwargs.get('host_id', None)
        self.exit_code = kwargs.get('exit_code', None)
        self.unexpected_termination = kwargs.get('unexpected_termination', None)
        self.start_time = kwargs.get('start_time', None)
        self.kind = 'ProcessDeactivated'
