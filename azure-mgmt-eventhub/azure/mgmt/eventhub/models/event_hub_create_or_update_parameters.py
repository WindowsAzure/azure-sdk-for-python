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


class EventHubCreateOrUpdateParameters(Model):
    """Parameters supplied to the Create Or Update Event Hub operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param location: Location of the resource.
    :type location: str
    :param type: ARM type of the Namespace.
    :type type: str
    :param name: Name of the Event Hub.
    :type name: str
    :ivar created_at: Exact time the Event Hub was created.
    :vartype created_at: datetime
    :param message_retention_in_days: Number of days to retain the events for
     this Event Hub.
    :type message_retention_in_days: long
    :param partition_count: Number of partitions created for the Event Hub.
    :type partition_count: long
    :ivar partition_ids: Current number of shards on the Event Hub.
    :vartype partition_ids: list of str
    :param status: Enumerates the possible values for the status of the Event
     Hub. Possible values include: 'Active', 'Disabled', 'Restoring',
     'SendDisabled', 'ReceiveDisabled', 'Creating', 'Deleting', 'Renaming',
     'Unknown'
    :type status: str or :class:`EntityStatus
     <azure.mgmt.eventhub.models.EntityStatus>`
    :ivar updated_at: The exact time the message was updated.
    :vartype updated_at: datetime
    """

    _validation = {
        'location': {'required': True},
        'created_at': {'readonly': True},
        'partition_ids': {'readonly': True},
        'updated_at': {'readonly': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'message_retention_in_days': {'key': 'properties.messageRetentionInDays', 'type': 'long'},
        'partition_count': {'key': 'properties.partitionCount', 'type': 'long'},
        'partition_ids': {'key': 'properties.partitionIds', 'type': '[str]'},
        'status': {'key': 'properties.status', 'type': 'EntityStatus'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
    }

    def __init__(self, location, type=None, name=None, message_retention_in_days=None, partition_count=None, status=None):
        self.location = location
        self.type = type
        self.name = name
        self.created_at = None
        self.message_retention_in_days = message_retention_in_days
        self.partition_count = partition_count
        self.partition_ids = None
        self.status = status
        self.updated_at = None
