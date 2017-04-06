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


class MigrateMySqlStatus(Resource):
    """MySQL migration status.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :param name: Resource Name.
    :type name: str
    :param kind: Kind of resource.
    :type kind: str
    :param location: Resource Location.
    :type location: str
    :param type: Resource type.
    :type type: str
    :param tags: Resource tags.
    :type tags: dict
    :ivar migration_operation_status: Status of the migration task. Possible
     values include: 'InProgress', 'Failed', 'Succeeded', 'TimedOut', 'Created'
    :vartype migration_operation_status: str or :class:`OperationStatus
     <azure.mgmt.web.models.OperationStatus>`
    :ivar operation_id: Operation ID for the migration task.
    :vartype operation_id: str
    :ivar local_my_sql_enabled: True if the web app has in app MySql enabled
    :vartype local_my_sql_enabled: bool
    """

    _validation = {
        'id': {'readonly': True},
        'location': {'required': True},
        'migration_operation_status': {'readonly': True},
        'operation_id': {'readonly': True},
        'local_my_sql_enabled': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'migration_operation_status': {'key': 'properties.migrationOperationStatus', 'type': 'OperationStatus'},
        'operation_id': {'key': 'properties.operationId', 'type': 'str'},
        'local_my_sql_enabled': {'key': 'properties.localMySqlEnabled', 'type': 'bool'},
    }

    def __init__(self, location, name=None, kind=None, type=None, tags=None):
        super(MigrateMySqlStatus, self).__init__(name=name, kind=kind, location=location, type=type, tags=tags)
        self.migration_operation_status = None
        self.operation_id = None
        self.local_my_sql_enabled = None
