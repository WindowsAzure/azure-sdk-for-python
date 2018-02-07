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

from .resource import Resource


class Module(Resource):
    """Definition of the module type.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param is_global: Gets or sets the isGlobal flag of the module.
    :type is_global: bool
    :param version: Gets or sets the version of the module.
    :type version: str
    :param size_in_bytes: Gets or sets the size in bytes of the module.
    :type size_in_bytes: long
    :param activity_count: Gets or sets the activity count of the module.
    :type activity_count: int
    :param provisioning_state: Gets or sets the provisioning state of the
     module. Possible values include: 'Created', 'Creating',
     'StartingImportModuleRunbook', 'RunningImportModuleRunbook',
     'ContentRetrieved', 'ContentDownloaded', 'ContentValidated',
     'ConnectionTypeImported', 'ContentStored', 'ModuleDataStored',
     'ActivitiesStored', 'ModuleImportRunbookComplete', 'Succeeded', 'Failed',
     'Cancelled', 'Updating'
    :type provisioning_state: str or
     ~azure.mgmt.automation.models.ModuleProvisioningState
    :param content_link: Gets or sets the contentLink of the module.
    :type content_link: ~azure.mgmt.automation.models.ContentLink
    :param error: Gets or sets the error info of the module.
    :type error: ~azure.mgmt.automation.models.ModuleErrorInfo
    :param creation_time: Gets or sets the creation time.
    :type creation_time: datetime
    :param last_modified_time: Gets or sets the last modified time.
    :type last_modified_time: datetime
    :param description: Gets or sets the description.
    :type description: str
    :param etag: Gets or sets the etag of the resource.
    :type etag: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'is_global': {'key': 'properties.isGlobal', 'type': 'bool'},
        'version': {'key': 'properties.version', 'type': 'str'},
        'size_in_bytes': {'key': 'properties.sizeInBytes', 'type': 'long'},
        'activity_count': {'key': 'properties.activityCount', 'type': 'int'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'ModuleProvisioningState'},
        'content_link': {'key': 'properties.contentLink', 'type': 'ContentLink'},
        'error': {'key': 'properties.error', 'type': 'ModuleErrorInfo'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'last_modified_time': {'key': 'properties.lastModifiedTime', 'type': 'iso-8601'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, location, tags=None, is_global=None, version=None, size_in_bytes=None, activity_count=None, provisioning_state=None, content_link=None, error=None, creation_time=None, last_modified_time=None, description=None, etag=None):
        super(Module, self).__init__(location=location, tags=tags)
        self.is_global = is_global
        self.version = version
        self.size_in_bytes = size_in_bytes
        self.activity_count = activity_count
        self.provisioning_state = provisioning_state
        self.content_link = content_link
        self.error = error
        self.creation_time = creation_time
        self.last_modified_time = last_modified_time
        self.description = description
        self.etag = etag
