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

from .tracked_resource import TrackedResource


class Project(TrackedResource):
    """A project resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param location: Required. Resource location.
    :type location: str
    :param source_platform: Required. Source platform for the project.
     Possible values include: 'SQL', 'Unknown'
    :type source_platform: str or
     ~azure.mgmt.datamigration.models.ProjectSourcePlatform
    :param target_platform: Required. Target platform for the project.
     Possible values include: 'SQLDB', 'SQLMI', 'Unknown'
    :type target_platform: str or
     ~azure.mgmt.datamigration.models.ProjectTargetPlatform
    :ivar creation_time: UTC Date and time when project was created
    :vartype creation_time: datetime
    :param source_connection_info: Information for connecting to source
    :type source_connection_info:
     ~azure.mgmt.datamigration.models.ConnectionInfo
    :param target_connection_info: Information for connecting to target
    :type target_connection_info:
     ~azure.mgmt.datamigration.models.ConnectionInfo
    :param databases_info: List of DatabaseInfo
    :type databases_info: list[~azure.mgmt.datamigration.models.DatabaseInfo]
    :ivar provisioning_state: The project's provisioning state. Possible
     values include: 'Deleting', 'Succeeded'
    :vartype provisioning_state: str or
     ~azure.mgmt.datamigration.models.ProjectProvisioningState
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'source_platform': {'required': True},
        'target_platform': {'required': True},
        'creation_time': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'source_platform': {'key': 'properties.sourcePlatform', 'type': 'str'},
        'target_platform': {'key': 'properties.targetPlatform', 'type': 'str'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'source_connection_info': {'key': 'properties.sourceConnectionInfo', 'type': 'ConnectionInfo'},
        'target_connection_info': {'key': 'properties.targetConnectionInfo', 'type': 'ConnectionInfo'},
        'databases_info': {'key': 'properties.databasesInfo', 'type': '[DatabaseInfo]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, *, location: str, source_platform, target_platform, tags=None, source_connection_info=None, target_connection_info=None, databases_info=None, **kwargs) -> None:
        super(Project, self).__init__(tags=tags, location=location, **kwargs)
        self.source_platform = source_platform
        self.target_platform = target_platform
        self.creation_time = None
        self.source_connection_info = source_connection_info
        self.target_connection_info = target_connection_info
        self.databases_info = databases_info
        self.provisioning_state = None
