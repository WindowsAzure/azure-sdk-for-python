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


class MongoDbProgress(Model):
    """Base class for MongoDB migration outputs.

    All required parameters must be populated in order to send to Azure.

    :param bytes_copied: Required. The number of document bytes copied during
     the Copying stage
    :type bytes_copied: long
    :param documents_copied: Required. The number of documents copied during
     the Copying stage
    :type documents_copied: long
    :param elapsed_time: Required. The elapsed time in the format
     [ddd.]hh:mm:ss[.fffffff] (i.e. TimeSpan format)
    :type elapsed_time: str
    :param errors: Required. The errors and warnings that have occurred for
     the current object. The keys are the error codes.
    :type errors: dict[str, ~azure.mgmt.datamigration.models.MongoDbError]
    :param events_pending: Required. The number of oplog events awaiting
     replay
    :type events_pending: long
    :param events_replayed: Required. The number of oplog events replayed so
     far
    :type events_replayed: long
    :param last_event_time: The timestamp of the last oplog event received, or
     null if no oplog event has been received yet
    :type last_event_time: datetime
    :param last_replay_time: The timestamp of the last oplog event replayed,
     or null if no oplog event has been replayed yet
    :type last_replay_time: datetime
    :param name: The name of the progress object. For a collection, this is
     the unqualified collection name. For a database, this is the database
     name. For the overall migration, this is null.
    :type name: str
    :param qualified_name: The qualified name of the progress object. For a
     collection, this is the database-qualified name. For a database, this is
     the database name. For the overall migration, this is null.
    :type qualified_name: str
    :param result_type: Required. The type of progress object. Possible values
     include: 'Migration', 'Database', 'Collection'
    :type result_type: str or ~azure.mgmt.datamigration.models.enum
    :param state: Required. Possible values include: 'NotStarted',
     'ValidatingInput', 'Initializing', 'Restarting', 'Copying',
     'InitialReplay', 'Replaying', 'Finalizing', 'Complete', 'Canceled',
     'Failed'
    :type state: str or ~azure.mgmt.datamigration.models.MongoDbMigrationState
    :param total_bytes: Required. The total number of document bytes on the
     source at the beginning of the Copying stage, or -1 if the total size was
     unknown
    :type total_bytes: long
    :param total_documents: Required. The total number of documents on the
     source at the beginning of the Copying stage, or -1 if the total count was
     unknown
    :type total_documents: long
    """

    _validation = {
        'bytes_copied': {'required': True},
        'documents_copied': {'required': True},
        'elapsed_time': {'required': True},
        'errors': {'required': True},
        'events_pending': {'required': True},
        'events_replayed': {'required': True},
        'result_type': {'required': True},
        'state': {'required': True},
        'total_bytes': {'required': True},
        'total_documents': {'required': True},
    }

    _attribute_map = {
        'bytes_copied': {'key': 'bytesCopied', 'type': 'long'},
        'documents_copied': {'key': 'documentsCopied', 'type': 'long'},
        'elapsed_time': {'key': 'elapsedTime', 'type': 'str'},
        'errors': {'key': 'errors', 'type': '{MongoDbError}'},
        'events_pending': {'key': 'eventsPending', 'type': 'long'},
        'events_replayed': {'key': 'eventsReplayed', 'type': 'long'},
        'last_event_time': {'key': 'lastEventTime', 'type': 'iso-8601'},
        'last_replay_time': {'key': 'lastReplayTime', 'type': 'iso-8601'},
        'name': {'key': 'name', 'type': 'str'},
        'qualified_name': {'key': 'qualifiedName', 'type': 'str'},
        'result_type': {'key': 'resultType', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'total_bytes': {'key': 'totalBytes', 'type': 'long'},
        'total_documents': {'key': 'totalDocuments', 'type': 'long'},
    }

    def __init__(self, **kwargs):
        super(MongoDbProgress, self).__init__(**kwargs)
        self.bytes_copied = kwargs.get('bytes_copied', None)
        self.documents_copied = kwargs.get('documents_copied', None)
        self.elapsed_time = kwargs.get('elapsed_time', None)
        self.errors = kwargs.get('errors', None)
        self.events_pending = kwargs.get('events_pending', None)
        self.events_replayed = kwargs.get('events_replayed', None)
        self.last_event_time = kwargs.get('last_event_time', None)
        self.last_replay_time = kwargs.get('last_replay_time', None)
        self.name = kwargs.get('name', None)
        self.qualified_name = kwargs.get('qualified_name', None)
        self.result_type = kwargs.get('result_type', None)
        self.state = kwargs.get('state', None)
        self.total_bytes = kwargs.get('total_bytes', None)
        self.total_documents = kwargs.get('total_documents', None)
