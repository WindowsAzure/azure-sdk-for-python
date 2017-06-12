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

from .proxy_resource import ProxyResource


class ElasticPoolActivity(ProxyResource):
    """Represents the activity on an elastic pool.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: The geo-location where the resource lives
    :type location: str
    :ivar end_time: The time the operation finished (ISO8601 format).
    :vartype end_time: datetime
    :ivar error_code: The error code if available.
    :vartype error_code: int
    :ivar error_message: The error message if available.
    :vartype error_message: str
    :ivar error_severity: The error severity if available.
    :vartype error_severity: int
    :ivar operation: The operation name.
    :vartype operation: str
    :ivar operation_id: The unique operation ID.
    :vartype operation_id: str
    :ivar percent_complete: The percentage complete if available.
    :vartype percent_complete: int
    :ivar requested_database_dtu_max: The requested max DTU per database if
     available.
    :vartype requested_database_dtu_max: int
    :ivar requested_database_dtu_min: The requested min DTU per database if
     available.
    :vartype requested_database_dtu_min: int
    :ivar requested_dtu: The requested DTU for the pool if available.
    :vartype requested_dtu: int
    :ivar requested_elastic_pool_name: The requested name for the elastic pool
     if available.
    :vartype requested_elastic_pool_name: str
    :ivar requested_storage_limit_in_gb: The requested storage limit for the
     pool in GB if available.
    :vartype requested_storage_limit_in_gb: long
    :ivar elastic_pool_name: The name of the elastic pool.
    :vartype elastic_pool_name: str
    :ivar server_name: The name of the server the elastic pool is in.
    :vartype server_name: str
    :ivar start_time: The time the operation started (ISO8601 format).
    :vartype start_time: datetime
    :ivar state: The current state of the operation.
    :vartype state: str
    :ivar requested_storage_limit_in_mb: The requested storage limit in MB.
    :vartype requested_storage_limit_in_mb: int
    :ivar requested_database_dtu_guarantee: The requested per database DTU
     guarantee.
    :vartype requested_database_dtu_guarantee: int
    :ivar requested_database_dtu_cap: The requested per database DTU cap.
    :vartype requested_database_dtu_cap: int
    :ivar requested_dtu_guarantee: The requested DTU guarantee.
    :vartype requested_dtu_guarantee: int
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'end_time': {'readonly': True},
        'error_code': {'readonly': True},
        'error_message': {'readonly': True},
        'error_severity': {'readonly': True},
        'operation': {'readonly': True},
        'operation_id': {'readonly': True},
        'percent_complete': {'readonly': True},
        'requested_database_dtu_max': {'readonly': True},
        'requested_database_dtu_min': {'readonly': True},
        'requested_dtu': {'readonly': True},
        'requested_elastic_pool_name': {'readonly': True},
        'requested_storage_limit_in_gb': {'readonly': True},
        'elastic_pool_name': {'readonly': True},
        'server_name': {'readonly': True},
        'start_time': {'readonly': True},
        'state': {'readonly': True},
        'requested_storage_limit_in_mb': {'readonly': True},
        'requested_database_dtu_guarantee': {'readonly': True},
        'requested_database_dtu_cap': {'readonly': True},
        'requested_dtu_guarantee': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'end_time': {'key': 'properties.endTime', 'type': 'iso-8601'},
        'error_code': {'key': 'properties.errorCode', 'type': 'int'},
        'error_message': {'key': 'properties.errorMessage', 'type': 'str'},
        'error_severity': {'key': 'properties.errorSeverity', 'type': 'int'},
        'operation': {'key': 'properties.operation', 'type': 'str'},
        'operation_id': {'key': 'properties.operationId', 'type': 'str'},
        'percent_complete': {'key': 'properties.percentComplete', 'type': 'int'},
        'requested_database_dtu_max': {'key': 'properties.requestedDatabaseDtuMax', 'type': 'int'},
        'requested_database_dtu_min': {'key': 'properties.requestedDatabaseDtuMin', 'type': 'int'},
        'requested_dtu': {'key': 'properties.requestedDtu', 'type': 'int'},
        'requested_elastic_pool_name': {'key': 'properties.requestedElasticPoolName', 'type': 'str'},
        'requested_storage_limit_in_gb': {'key': 'properties.requestedStorageLimitInGB', 'type': 'long'},
        'elastic_pool_name': {'key': 'properties.elasticPoolName', 'type': 'str'},
        'server_name': {'key': 'properties.serverName', 'type': 'str'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'requested_storage_limit_in_mb': {'key': 'properties.requestedStorageLimitInMB', 'type': 'int'},
        'requested_database_dtu_guarantee': {'key': 'properties.requestedDatabaseDtuGuarantee', 'type': 'int'},
        'requested_database_dtu_cap': {'key': 'properties.requestedDatabaseDtuCap', 'type': 'int'},
        'requested_dtu_guarantee': {'key': 'properties.requestedDtuGuarantee', 'type': 'int'},
    }

    def __init__(self, location=None):
        super(ElasticPoolActivity, self).__init__()
        self.location = location
        self.end_time = None
        self.error_code = None
        self.error_message = None
        self.error_severity = None
        self.operation = None
        self.operation_id = None
        self.percent_complete = None
        self.requested_database_dtu_max = None
        self.requested_database_dtu_min = None
        self.requested_dtu = None
        self.requested_elastic_pool_name = None
        self.requested_storage_limit_in_gb = None
        self.elastic_pool_name = None
        self.server_name = None
        self.start_time = None
        self.state = None
        self.requested_storage_limit_in_mb = None
        self.requested_database_dtu_guarantee = None
        self.requested_database_dtu_cap = None
        self.requested_dtu_guarantee = None
