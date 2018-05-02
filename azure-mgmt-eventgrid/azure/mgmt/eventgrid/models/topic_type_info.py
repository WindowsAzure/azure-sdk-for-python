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


class TopicTypeInfo(Resource):
    """Properties of a topic type info.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified identifier of the resource
    :vartype id: str
    :ivar name: Name of the resource
    :vartype name: str
    :ivar type: Type of the resource
    :vartype type: str
    :param provider: Namespace of the provider of the topic type.
    :type provider: str
    :param display_name: Display Name for the topic type.
    :type display_name: str
    :param description: Description of the topic type.
    :type description: str
    :param resource_region_type: Region type of the resource. Possible values
     include: 'RegionalResource', 'GlobalResource'
    :type resource_region_type: str or
     ~azure.mgmt.eventgrid.models.ResourceRegionType
    :param provisioning_state: Provisioning state of the topic type. Possible
     values include: 'Creating', 'Updating', 'Deleting', 'Succeeded',
     'Canceled', 'Failed'
    :type provisioning_state: str or
     ~azure.mgmt.eventgrid.models.TopicTypeProvisioningState
    :param supported_locations: List of locations supported by this topic
     type.
    :type supported_locations: list[str]
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
        'provider': {'key': 'properties.provider', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'resource_region_type': {'key': 'properties.resourceRegionType', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'supported_locations': {'key': 'properties.supportedLocations', 'type': '[str]'},
    }

    def __init__(self, provider=None, display_name=None, description=None, resource_region_type=None, provisioning_state=None, supported_locations=None):
        super(TopicTypeInfo, self).__init__()
        self.provider = provider
        self.display_name = display_name
        self.description = description
        self.resource_region_type = resource_region_type
        self.provisioning_state = provisioning_state
        self.supported_locations = supported_locations
