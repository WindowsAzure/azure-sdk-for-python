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


class BuildTask(Resource):
    """The build task that has the resource properties and all build items. The
    build task will have all information to schedule a build against it.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param location: Required. The location of the resource. This cannot be
     changed after the resource is created.
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :ivar provisioning_state: The provisioning state of the build task.
     Possible values include: 'Creating', 'Updating', 'Deleting', 'Succeeded',
     'Failed', 'Canceled'
    :vartype provisioning_state: str or
     ~azure.mgmt.containerregistry.v2018_02_01_preview.models.ProvisioningState
    :ivar creation_date: The creation date of build task.
    :vartype creation_date: datetime
    :param alias: Required. The alternative updatable name for a build task.
    :type alias: str
    :param status: The current status of build task. Possible values include:
     'Disabled', 'Enabled'
    :type status: str or
     ~azure.mgmt.containerregistry.v2018_02_01_preview.models.BuildTaskStatus
    :param source_repository: Required. The properties that describes the
     source(code) for the build task.
    :type source_repository:
     ~azure.mgmt.containerregistry.v2018_02_01_preview.models.SourceRepositoryProperties
    :param platform: Required. The platform properties against which the build
     has to happen.
    :type platform:
     ~azure.mgmt.containerregistry.v2018_02_01_preview.models.PlatformProperties
    :param timeout: Build timeout in seconds. Default value: 3600 .
    :type timeout: int
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'creation_date': {'readonly': True},
        'alias': {'required': True},
        'source_repository': {'required': True},
        'platform': {'required': True},
        'timeout': {'maximum': 28800, 'minimum': 300},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'creation_date': {'key': 'properties.creationDate', 'type': 'iso-8601'},
        'alias': {'key': 'properties.alias', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'source_repository': {'key': 'properties.sourceRepository', 'type': 'SourceRepositoryProperties'},
        'platform': {'key': 'properties.platform', 'type': 'PlatformProperties'},
        'timeout': {'key': 'properties.timeout', 'type': 'int'},
    }

    def __init__(self, *, location: str, alias: str, source_repository, platform, tags=None, status=None, timeout: int=3600, **kwargs) -> None:
        super(BuildTask, self).__init__(location=location, tags=tags, **kwargs)
        self.provisioning_state = None
        self.creation_date = None
        self.alias = alias
        self.status = status
        self.source_repository = source_repository
        self.platform = platform
        self.timeout = timeout
