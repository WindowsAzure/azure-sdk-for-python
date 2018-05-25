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

from .resource_py3 import Resource


class PowerShellSessionResource(Resource):
    """A PowerShell session resource (practically equivalent to a runspace
    instance).

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Manager Resource ID.
    :vartype id: str
    :ivar type: Resource Manager Resource Type.
    :vartype type: str
    :ivar name: Resource Manager Resource Name.
    :vartype name: str
    :ivar location: Resource Manager Resource Location.
    :vartype location: str
    :param tags: Resource Manager Resource Tags.
    :type tags: dict[str, str]
    :param etag:
    :type etag: str
    :param session_id: The PowerShell Session ID.
    :type session_id: str
    :param state: The runspace state.
    :type state: str
    :param runspace_availability: The availability of the runspace.
    :type runspace_availability: str
    :param disconnected_on: Timestamp of last time the service disconnected
     from the runspace.
    :type disconnected_on: datetime
    :param expires_on: Timestamp when the runspace expires.
    :type expires_on: datetime
    :param version:
    :type version: ~azure.mgmt.servermanagement.models.Version
    :param power_shell_session_resource_name: Name of the runspace.
    :type power_shell_session_resource_name: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'location': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'etag': {'key': 'etag', 'type': 'str'},
        'session_id': {'key': 'properties.sessionId', 'type': 'str'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'runspace_availability': {'key': 'properties.runspaceAvailability', 'type': 'str'},
        'disconnected_on': {'key': 'properties.disconnectedOn', 'type': 'iso-8601'},
        'expires_on': {'key': 'properties.expiresOn', 'type': 'iso-8601'},
        'version': {'key': 'properties.version', 'type': 'Version'},
        'power_shell_session_resource_name': {'key': 'properties.name', 'type': 'str'},
    }

    def __init__(self, *, tags=None, etag: str=None, session_id: str=None, state: str=None, runspace_availability: str=None, disconnected_on=None, expires_on=None, version=None, power_shell_session_resource_name: str=None, **kwargs) -> None:
        super(PowerShellSessionResource, self).__init__(tags=tags, etag=etag, **kwargs)
        self.session_id = session_id
        self.state = state
        self.runspace_availability = runspace_availability
        self.disconnected_on = disconnected_on
        self.expires_on = expires_on
        self.version = version
        self.power_shell_session_resource_name = power_shell_session_resource_name
