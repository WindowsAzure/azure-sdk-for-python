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

from msrest.serialization import Model


class ConsumerGroupCreateOrUpdateParameters(Model):
    """Parameters supplied to the Create Or Update Consumer Group operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. Location of the resource.
    :type location: str
    :param type: ARM type of the Namespace.
    :type type: str
    :param name: Name of the consumer group.
    :type name: str
    :ivar created_at: Exact time the message was created.
    :vartype created_at: datetime
    :ivar event_hub_path: The path of the Event Hub.
    :vartype event_hub_path: str
    :ivar updated_at: The exact time the message was updated.
    :vartype updated_at: datetime
    :param user_metadata: The user metadata.
    :type user_metadata: str
    """

    _validation = {
        'location': {'required': True},
        'created_at': {'readonly': True},
        'event_hub_path': {'readonly': True},
        'updated_at': {'readonly': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'event_hub_path': {'key': 'properties.eventHubPath', 'type': 'str'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'user_metadata': {'key': 'properties.userMetadata', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ConsumerGroupCreateOrUpdateParameters, self).__init__(**kwargs)
        self.location = kwargs.get('location', None)
        self.type = kwargs.get('type', None)
        self.name = kwargs.get('name', None)
        self.created_at = None
        self.event_hub_path = None
        self.updated_at = None
        self.user_metadata = kwargs.get('user_metadata', None)
