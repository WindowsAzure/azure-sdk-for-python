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


class Workspace(Resource):
    """An object that represents a machine learning workspace.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Specifies the resource ID.
    :vartype id: str
    :ivar name: Specifies the name of the resource.
    :vartype name: str
    :ivar identity: The identity of the resource.
    :vartype identity: ~azure.mgmt.machinelearningservices.models.Identity
    :param location: Specifies the location of the resource.
    :type location: str
    :ivar type: Specifies the type of the resource.
    :vartype type: str
    :param tags: Contains resource tags defined as key/value pairs.
    :type tags: dict[str, str]
    :ivar workspace_id: The immutable id associated with this workspace.
    :vartype workspace_id: str
    :param description: The description of this workspace.
    :type description: str
    :param friendly_name: The friendly name for this workspace. This name in
     mutable
    :type friendly_name: str
    :ivar creation_time: The creation time of the machine learning workspace
     in ISO8601 format.
    :vartype creation_time: datetime
    :param key_vault: ARM id of the key vault associated with this workspace.
     This cannot be changed once the workspace has been created
    :type key_vault: str
    :param application_insights: ARM id of the application insights associated
     with this workspace. This cannot be changed once the workspace has been
     created
    :type application_insights: str
    :param container_registry: ARM id of the container registry associated
     with this workspace. This cannot be changed once the workspace has been
     created
    :type container_registry: str
    :param storage_account: ARM id of the storage account associated with this
     workspace. This cannot be changed once the workspace has been created
    :type storage_account: str
    :param discovery_url: Url for the discovery service to identify regional
     endpoints for machine learning experimentation services
    :type discovery_url: str
    :ivar provisioning_state: The current deployment state of workspace
     resource. The provisioningState is to indicate states for resource
     provisioning. Possible values include: 'Unknown', 'Updating', 'Creating',
     'Deleting', 'Succeeded', 'Failed', 'Canceled'
    :vartype provisioning_state: str or
     ~azure.mgmt.machinelearningservices.models.ProvisioningState
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'identity': {'readonly': True},
        'type': {'readonly': True},
        'workspace_id': {'readonly': True},
        'creation_time': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'Identity'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'workspace_id': {'key': 'properties.workspaceId', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'friendly_name': {'key': 'properties.friendlyName', 'type': 'str'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'key_vault': {'key': 'properties.keyVault', 'type': 'str'},
        'application_insights': {'key': 'properties.applicationInsights', 'type': 'str'},
        'container_registry': {'key': 'properties.containerRegistry', 'type': 'str'},
        'storage_account': {'key': 'properties.storageAccount', 'type': 'str'},
        'discovery_url': {'key': 'properties.discoveryUrl', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, tags=None, description: str=None, friendly_name: str=None, key_vault: str=None, application_insights: str=None, container_registry: str=None, storage_account: str=None, discovery_url: str=None, **kwargs) -> None:
        super(Workspace, self).__init__(location=location, tags=tags, **kwargs)
        self.workspace_id = None
        self.description = description
        self.friendly_name = friendly_name
        self.creation_time = None
        self.key_vault = key_vault
        self.application_insights = application_insights
        self.container_registry = container_registry
        self.storage_account = storage_account
        self.discovery_url = discovery_url
        self.provisioning_state = None
