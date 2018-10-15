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


class NotificationChannelFragment(Resource):
    """A notification.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The identifier of the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param location: The location of the resource.
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :param web_hook_url: The webhook URL to send notifications to.
    :type web_hook_url: str
    :param description: Description of notification.
    :type description: str
    :param events: The list of event for which this notification is enabled.
    :type events: list[~azure.mgmt.devtestlabs.models.EventFragment]
    :param provisioning_state: The provisioning status of the resource.
    :type provisioning_state: str
    :param unique_identifier: The unique immutable identifier of a resource
     (Guid).
    :type unique_identifier: str
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
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'web_hook_url': {'key': 'properties.webHookUrl', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'events': {'key': 'properties.events', 'type': '[EventFragment]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'unique_identifier': {'key': 'properties.uniqueIdentifier', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(NotificationChannelFragment, self).__init__(**kwargs)
        self.web_hook_url = kwargs.get('web_hook_url', None)
        self.description = kwargs.get('description', None)
        self.events = kwargs.get('events', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.unique_identifier = kwargs.get('unique_identifier', None)
