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

from .external_security_solution_properties_py3 import ExternalSecuritySolutionProperties


class CefSolutionProperties(ExternalSecuritySolutionProperties):
    """The external security solution properties for CEF solutions.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param device_vendor:
    :type device_vendor: str
    :param device_type:
    :type device_type: str
    :param workspace:
    :type workspace: ~azure.mgmt.security.models.ConnectedWorkspace
    :param hostname:
    :type hostname: str
    :param agent:
    :type agent: str
    :param last_event_received:
    :type last_event_received: str
    """

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'device_vendor': {'key': 'deviceVendor', 'type': 'str'},
        'device_type': {'key': 'deviceType', 'type': 'str'},
        'workspace': {'key': 'workspace', 'type': 'ConnectedWorkspace'},
        'hostname': {'key': 'hostname', 'type': 'str'},
        'agent': {'key': 'agent', 'type': 'str'},
        'last_event_received': {'key': 'lastEventReceived', 'type': 'str'},
    }

    def __init__(self, *, additional_properties=None, device_vendor: str=None, device_type: str=None, workspace=None, hostname: str=None, agent: str=None, last_event_received: str=None, **kwargs) -> None:
        super(CefSolutionProperties, self).__init__(additional_properties=additional_properties, device_vendor=device_vendor, device_type=device_type, workspace=workspace, **kwargs)
        self.hostname = hostname
        self.agent = agent
        self.last_event_received = last_event_received
