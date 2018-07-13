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

from .proxy_only_resource_py3 import ProxyOnlyResource


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
    :ivar identifier: Site extension ID.
    :vartype identifier: int
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
        'identifier': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'identifier': {'key': 'properties.identifier', 'type': 'int'},
        'href': {'key': 'properties.href', 'type': 'str'},
        'process': {'key': 'properties.process', 'type': 'str'},
        'start_address': {'key': 'properties.start_address', 'type': 'str'},
        'current_priority': {'key': 'properties.current_priority', 'type': 'int'},
        'priority_level': {'key': 'properties.priority_level', 'type': 'str'},
        'base_priority': {'key': 'properties.base_priority', 'type': 'int'},
        'start_time': {'key': 'properties.start_time', 'type': 'iso-8601'},
        'total_processor_time': {'key': 'properties.total_processor_time', 'type': 'str'},
        'user_processor_time': {'key': 'properties.user_processor_time', 'type': 'str'},
        'priviledged_processor_time': {'key': 'properties.priviledged_processor_time', 'type': 'str'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'wait_reason': {'key': 'properties.wait_reason', 'type': 'str'},
    }

    def __init__(self, *, kind: str=None, href: str=None, process: str=None, start_address: str=None, current_priority: int=None, priority_level: str=None, base_priority: int=None, start_time=None, total_processor_time: str=None, user_processor_time: str=None, priviledged_processor_time: str=None, state: str=None, wait_reason: str=None, **kwargs) -> None:
        super(ProcessThreadInfo, self).__init__(kind=kind, **kwargs)
        self.identifier = None
        self.href = href
        self.process = process
        self.start_address = start_address
        self.current_priority = current_priority
        self.priority_level = priority_level
        self.base_priority = base_priority
        self.start_time = start_time
        self.total_processor_time = total_processor_time
        self.user_processor_time = user_processor_time
        self.priviledged_processor_time = priviledged_processor_time
        self.state = state
        self.wait_reason = wait_reason
