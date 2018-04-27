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

from .proxy_only_resource import ProxyOnlyResource


class ProcessThreadInfo(ProxyOnlyResource):
    """Process Thread Information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param process_thread_info_id: ARM Identifier for deployment.
    :type process_thread_info_id: int
    :param href: HRef URI.
    :type href: str
    :param process: Process URI.
    :type process: str
    :param start_address: Start address.
    :type start_address: str
    :param current_priority: Current thread priority.
    :type current_priority: int
    :param priority_level: Thread priority level.
    :type priority_level: str
    :param base_priority: Base priority.
    :type base_priority: int
    :param start_time: Start time.
    :type start_time: datetime
    :param total_processor_time: Total processor time.
    :type total_processor_time: str
    :param user_processor_time: User processor time.
    :type user_processor_time: str
    :param priviledged_processor_time: Priviledged processor time.
    :type priviledged_processor_time: str
    :param state: Thread state.
    :type state: str
    :param wait_reason: Wait reason.
    :type wait_reason: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'process_thread_info_id': {'key': 'properties.id', 'type': 'int'},
        'href': {'key': 'properties.href', 'type': 'str'},
        'process': {'key': 'properties.process', 'type': 'str'},
        'start_address': {'key': 'properties.startAddress', 'type': 'str'},
        'current_priority': {'key': 'properties.currentPriority', 'type': 'int'},
        'priority_level': {'key': 'properties.priorityLevel', 'type': 'str'},
        'base_priority': {'key': 'properties.basePriority', 'type': 'int'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'total_processor_time': {'key': 'properties.totalProcessorTime', 'type': 'str'},
        'user_processor_time': {'key': 'properties.userProcessorTime', 'type': 'str'},
        'priviledged_processor_time': {'key': 'properties.priviledgedProcessorTime', 'type': 'str'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'wait_reason': {'key': 'properties.waitReason', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ProcessThreadInfo, self).__init__(**kwargs)
        self.process_thread_info_id = kwargs.get('process_thread_info_id', None)
        self.href = kwargs.get('href', None)
        self.process = kwargs.get('process', None)
        self.start_address = kwargs.get('start_address', None)
        self.current_priority = kwargs.get('current_priority', None)
        self.priority_level = kwargs.get('priority_level', None)
        self.base_priority = kwargs.get('base_priority', None)
        self.start_time = kwargs.get('start_time', None)
        self.total_processor_time = kwargs.get('total_processor_time', None)
        self.user_processor_time = kwargs.get('user_processor_time', None)
        self.priviledged_processor_time = kwargs.get('priviledged_processor_time', None)
        self.state = kwargs.get('state', None)
        self.wait_reason = kwargs.get('wait_reason', None)
