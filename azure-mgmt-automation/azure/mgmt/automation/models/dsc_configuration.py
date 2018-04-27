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


class DscConfiguration(TrackedResource):
    """Definition of the configuration type.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param location: The Azure Region where the resource lives
    :type location: str
    :param provisioning_state: Gets or sets the provisioning state of the
     configuration. Possible values include: 'Succeeded'
    :type provisioning_state: str or
     ~azure.mgmt.automation.models.DscConfigurationProvisioningState
    :param job_count: Gets or sets the job count of the configuration.
    :type job_count: int
    :param parameters: Gets or sets the configuration parameters.
    :type parameters: dict[str,
     ~azure.mgmt.automation.models.DscConfigurationParameter]
    :param source: Gets or sets the source.
    :type source: ~azure.mgmt.automation.models.ContentSource
    :param state: Gets or sets the state of the configuration. Possible values
     include: 'New', 'Edit', 'Published'
    :type state: str or ~azure.mgmt.automation.models.DscConfigurationState
    :param log_verbose: Gets or sets verbose log option.
    :type log_verbose: bool
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
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'DscConfigurationProvisioningState'},
        'job_count': {'key': 'properties.jobCount', 'type': 'int'},
        'parameters': {'key': 'properties.parameters', 'type': '{DscConfigurationParameter}'},
        'source': {'key': 'properties.source', 'type': 'ContentSource'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'log_verbose': {'key': 'properties.logVerbose', 'type': 'bool'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'last_modified_time': {'key': 'properties.lastModifiedTime', 'type': 'iso-8601'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(DscConfiguration, self).__init__(**kwargs)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.job_count = kwargs.get('job_count', None)
        self.parameters = kwargs.get('parameters', None)
        self.source = kwargs.get('source', None)
        self.state = kwargs.get('state', None)
        self.log_verbose = kwargs.get('log_verbose', None)
        self.creation_time = kwargs.get('creation_time', None)
        self.last_modified_time = kwargs.get('last_modified_time', None)
        self.description = kwargs.get('description', None)
        self.etag = kwargs.get('etag', None)
