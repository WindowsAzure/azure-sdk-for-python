# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class AccessPolicy(msrest.serialization.Model):
    """An Access policy.

    All required parameters must be populated in order to send to Azure.

    :param start: Required. The start datetime from which the policy is active.
    :type start: str
    :param expiry: Required. The datetime that the policy expires.
    :type expiry: str
    :param permission: Required. The permissions for the acl policy.
    :type permission: str
    """

    _validation = {
        'start': {'required': True},
        'expiry': {'required': True},
        'permission': {'required': True},
    }

    _attribute_map = {
        'start': {'key': 'Start', 'type': 'str', 'xml': {'name': 'Start'}},
        'expiry': {'key': 'Expiry', 'type': 'str', 'xml': {'name': 'Expiry'}},
        'permission': {'key': 'Permission', 'type': 'str', 'xml': {'name': 'Permission'}},
    }
    _xml_map = {
        'name': 'AccessPolicy'
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AccessPolicy, self).__init__(**kwargs)
        self.start = kwargs['start']
        self.expiry = kwargs['expiry']
        self.permission = kwargs['permission']


class CorsRule(msrest.serialization.Model):
    """CORS is an HTTP feature that enables a web application running under one domain to access resources in another domain. Web browsers implement a security restriction known as same-origin policy that prevents a web page from calling APIs in a different domain; CORS provides a secure way to allow one domain (the origin domain) to call APIs in another domain.

    All required parameters must be populated in order to send to Azure.

    :param allowed_origins: Required. The origin domains that are permitted to make a request
     against the service via CORS. The origin domain is the domain from which the request
     originates. Note that the origin must be an exact case-sensitive match with the origin that the
     user age sends to the service. You can also use the wildcard character '*' to allow all origin
     domains to make requests via CORS.
    :type allowed_origins: str
    :param allowed_methods: Required. The methods (HTTP request verbs) that the origin domain may
     use for a CORS request. (comma separated).
    :type allowed_methods: str
    :param allowed_headers: Required. The request headers that the origin domain may specify on the
     CORS request.
    :type allowed_headers: str
    :param exposed_headers: Required. The response headers that may be sent in the response to the
     CORS request and exposed by the browser to the request issuer.
    :type exposed_headers: str
    :param max_age_in_seconds: Required. The maximum amount time that a browser should cache the
     preflight OPTIONS request.
    :type max_age_in_seconds: int
    """

    _validation = {
        'allowed_origins': {'required': True},
        'allowed_methods': {'required': True},
        'allowed_headers': {'required': True},
        'exposed_headers': {'required': True},
        'max_age_in_seconds': {'required': True, 'minimum': 0},
    }

    _attribute_map = {
        'allowed_origins': {'key': 'AllowedOrigins', 'type': 'str', 'xml': {'name': 'AllowedOrigins'}},
        'allowed_methods': {'key': 'AllowedMethods', 'type': 'str', 'xml': {'name': 'AllowedMethods'}},
        'allowed_headers': {'key': 'AllowedHeaders', 'type': 'str', 'xml': {'name': 'AllowedHeaders'}},
        'exposed_headers': {'key': 'ExposedHeaders', 'type': 'str', 'xml': {'name': 'ExposedHeaders'}},
        'max_age_in_seconds': {'key': 'MaxAgeInSeconds', 'type': 'int', 'xml': {'name': 'MaxAgeInSeconds'}},
    }
    _xml_map = {
        'name': 'CorsRule'
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CorsRule, self).__init__(**kwargs)
        self.allowed_origins = kwargs['allowed_origins']
        self.allowed_methods = kwargs['allowed_methods']
        self.allowed_headers = kwargs['allowed_headers']
        self.exposed_headers = kwargs['exposed_headers']
        self.max_age_in_seconds = kwargs['max_age_in_seconds']


class GeoReplication(msrest.serialization.Model):
    """GeoReplication.

    All required parameters must be populated in order to send to Azure.

    :param status: Required. The status of the secondary location. Possible values include: "live",
     "bootstrap", "unavailable".
    :type status: str or ~azure.data.tables.models.GeoReplicationStatusType
    :param last_sync_time: Required. A GMT date/time value, to the second. All primary writes
     preceding this value are guaranteed to be available for read operations at the secondary.
     Primary writes after this point in time may or may not be available for reads.
    :type last_sync_time: ~datetime.datetime
    """

    _validation = {
        'status': {'required': True},
        'last_sync_time': {'required': True},
    }

    _attribute_map = {
        'status': {'key': 'Status', 'type': 'str', 'xml': {'name': 'Status'}},
        'last_sync_time': {'key': 'LastSyncTime', 'type': 'rfc-1123', 'xml': {'name': 'LastSyncTime'}},
    }
    _xml_map = {
        'name': 'GeoReplication'
    }

    def __init__(
        self,
        **kwargs
    ):
        super(GeoReplication, self).__init__(**kwargs)
        self.status = kwargs['status']
        self.last_sync_time = kwargs['last_sync_time']


class Logging(msrest.serialization.Model):
    """Azure Analytics Logging settings.

    All required parameters must be populated in order to send to Azure.

    :param version: Required. The version of Analytics to configure.
    :type version: str
    :param delete: Required. Indicates whether all delete requests should be logged.
    :type delete: bool
    :param read: Required. Indicates whether all read requests should be logged.
    :type read: bool
    :param write: Required. Indicates whether all write requests should be logged.
    :type write: bool
    :param retention_policy: Required. The retention policy.
    :type retention_policy: ~azure.data.tables.models.RetentionPolicy
    """

    _validation = {
        'version': {'required': True},
        'delete': {'required': True},
        'read': {'required': True},
        'write': {'required': True},
        'retention_policy': {'required': True},
    }

    _attribute_map = {
        'version': {'key': 'Version', 'type': 'str', 'xml': {'name': 'Version'}},
        'delete': {'key': 'Delete', 'type': 'bool', 'xml': {'name': 'Delete'}},
        'read': {'key': 'Read', 'type': 'bool', 'xml': {'name': 'Read'}},
        'write': {'key': 'Write', 'type': 'bool', 'xml': {'name': 'Write'}},
        'retention_policy': {'key': 'RetentionPolicy', 'type': 'RetentionPolicy'},
    }
    _xml_map = {
        'name': 'Logging'
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Logging, self).__init__(**kwargs)
        self.version = kwargs['version']
        self.delete = kwargs['delete']
        self.read = kwargs['read']
        self.write = kwargs['write']
        self.retention_policy = kwargs['retention_policy']


class Metrics(msrest.serialization.Model):
    """Metrics.

    All required parameters must be populated in order to send to Azure.

    :param version: The version of Analytics to configure.
    :type version: str
    :param enabled: Required. Indicates whether metrics are enabled for the Table service.
    :type enabled: bool
    :param include_apis: Indicates whether metrics should generate summary statistics for called
     API operations.
    :type include_apis: bool
    :param retention_policy: The retention policy.
    :type retention_policy: ~azure.data.tables.models.RetentionPolicy
    """

    _validation = {
        'enabled': {'required': True},
    }

    _attribute_map = {
        'version': {'key': 'Version', 'type': 'str', 'xml': {'name': 'Version'}},
        'enabled': {'key': 'Enabled', 'type': 'bool', 'xml': {'name': 'Enabled'}},
        'include_apis': {'key': 'IncludeAPIs', 'type': 'bool', 'xml': {'name': 'IncludeAPIs'}},
        'retention_policy': {'key': 'RetentionPolicy', 'type': 'RetentionPolicy'},
    }
    _xml_map = {
        
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Metrics, self).__init__(**kwargs)
        self.version = kwargs.get('version', None)
        self.enabled = kwargs['enabled']
        self.include_apis = kwargs.get('include_apis', None)
        self.retention_policy = kwargs.get('retention_policy', None)


class QueryOptions(msrest.serialization.Model):
    """Parameter group.

    :param format: Specifies the media type for the response. Possible values include:
     "application/json;odata=nometadata", "application/json;odata=minimalmetadata",
     "application/json;odata=fullmetadata".
    :type format: str or ~azure.data.tables.models.OdataMetadataFormat
    :param top: Maximum number of records to return.
    :type top: int
    :param select: Select expression using OData notation. Limits the columns on each record to
     just those requested, e.g. "$select=PolicyAssignmentId, ResourceId".
    :type select: str
    :param filter: OData filter expression.
    :type filter: str
    """

    _validation = {
        'top': {'minimum': 0},
    }

    _attribute_map = {
        'format': {'key': 'Format', 'type': 'str'},
        'top': {'key': 'Top', 'type': 'int'},
        'select': {'key': 'Select', 'type': 'str'},
        'filter': {'key': 'Filter', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(QueryOptions, self).__init__(**kwargs)
        self.format = kwargs.get('format', None)
        self.top = kwargs.get('top', None)
        self.select = kwargs.get('select', None)
        self.filter = kwargs.get('filter', None)


class RetentionPolicy(msrest.serialization.Model):
    """The retention policy.

    All required parameters must be populated in order to send to Azure.

    :param enabled: Required. Indicates whether a retention policy is enabled for the service.
    :type enabled: bool
    :param days: Indicates the number of days that metrics or logging or soft-deleted data should
     be retained. All data older than this value will be deleted.
    :type days: int
    """

    _validation = {
        'enabled': {'required': True},
        'days': {'minimum': 1},
    }

    _attribute_map = {
        'enabled': {'key': 'Enabled', 'type': 'bool', 'xml': {'name': 'Enabled'}},
        'days': {'key': 'Days', 'type': 'int', 'xml': {'name': 'Days'}},
    }
    _xml_map = {
        'name': 'RetentionPolicy'
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RetentionPolicy, self).__init__(**kwargs)
        self.enabled = kwargs['enabled']
        self.days = kwargs.get('days', None)


class SignedIdentifier(msrest.serialization.Model):
    """A signed identifier.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. A unique id.
    :type id: str
    :param access_policy: The access policy.
    :type access_policy: ~azure.data.tables.models.AccessPolicy
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'Id', 'type': 'str', 'xml': {'name': 'Id'}},
        'access_policy': {'key': 'AccessPolicy', 'type': 'AccessPolicy'},
    }
    _xml_map = {
        'name': 'SignedIdentifier'
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SignedIdentifier, self).__init__(**kwargs)
        self.id = kwargs['id']
        self.access_policy = kwargs.get('access_policy', None)


class TableEntityQueryResponse(msrest.serialization.Model):
    """The properties for the table entity query response.

    :param odata_metadata: The metadata response of the table.
    :type odata_metadata: str
    :param value: List of table entities.
    :type value: list[dict[str, object]]
    """

    _attribute_map = {
        'odata_metadata': {'key': 'odata\\.metadata', 'type': 'str'},
        'value': {'key': 'value', 'type': '[{object}]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TableEntityQueryResponse, self).__init__(**kwargs)
        self.odata_metadata = kwargs.get('odata_metadata', None)
        self.value = kwargs.get('value', None)


class TableProperties(msrest.serialization.Model):
    """The properties for creating a table.

    :param table_name: The name of the table to create.
    :type table_name: str
    """

    _attribute_map = {
        'table_name': {'key': 'TableName', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TableProperties, self).__init__(**kwargs)
        self.table_name = kwargs.get('table_name', None)


class TableQueryResponse(msrest.serialization.Model):
    """The properties for the table query response.

    :param odata_metadata: The metadata response of the table.
    :type odata_metadata: str
    :param value: List of tables.
    :type value: list[~azure.data.tables.models.TableResponseProperties]
    """

    _attribute_map = {
        'odata_metadata': {'key': 'odata\\.metadata', 'type': 'str'},
        'value': {'key': 'value', 'type': '[TableResponseProperties]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TableQueryResponse, self).__init__(**kwargs)
        self.odata_metadata = kwargs.get('odata_metadata', None)
        self.value = kwargs.get('value', None)


class TableResponseProperties(msrest.serialization.Model):
    """The properties for the table response.

    :param table_name: The name of the table.
    :type table_name: str
    :param odata_type: The odata type of the table.
    :type odata_type: str
    :param odata_id: The id of the table.
    :type odata_id: str
    :param odata_edit_link: The edit link of the table.
    :type odata_edit_link: str
    """

    _attribute_map = {
        'table_name': {'key': 'TableName', 'type': 'str'},
        'odata_type': {'key': 'odata\\.type', 'type': 'str'},
        'odata_id': {'key': 'odata\\.id', 'type': 'str'},
        'odata_edit_link': {'key': 'odata\\.editLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TableResponseProperties, self).__init__(**kwargs)
        self.table_name = kwargs.get('table_name', None)
        self.odata_type = kwargs.get('odata_type', None)
        self.odata_id = kwargs.get('odata_id', None)
        self.odata_edit_link = kwargs.get('odata_edit_link', None)


class TableResponse(TableResponseProperties):
    """The response for a single table.

    :param table_name: The name of the table.
    :type table_name: str
    :param odata_type: The odata type of the table.
    :type odata_type: str
    :param odata_id: The id of the table.
    :type odata_id: str
    :param odata_edit_link: The edit link of the table.
    :type odata_edit_link: str
    :param odata_metadata: The metadata response of the table.
    :type odata_metadata: str
    """

    _attribute_map = {
        'table_name': {'key': 'TableName', 'type': 'str'},
        'odata_type': {'key': 'odata\\.type', 'type': 'str'},
        'odata_id': {'key': 'odata\\.id', 'type': 'str'},
        'odata_edit_link': {'key': 'odata\\.editLink', 'type': 'str'},
        'odata_metadata': {'key': 'odata\\.metadata', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TableResponse, self).__init__(**kwargs)
        self.odata_metadata = kwargs.get('odata_metadata', None)


class TableServiceError(msrest.serialization.Model):
    """Table Service error.

    :param message: The error message.
    :type message: str
    """

    _attribute_map = {
        'message': {'key': 'Message', 'type': 'str', 'xml': {'name': 'Message'}},
    }
    _xml_map = {
        
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TableServiceError, self).__init__(**kwargs)
        self.message = kwargs.get('message', None)


class TableServiceProperties(msrest.serialization.Model):
    """Table Service Properties.

    :param logging: Azure Analytics Logging settings.
    :type logging: ~azure.data.tables.models.Logging
    :param hour_metrics: A summary of request statistics grouped by API in hourly aggregates for
     tables.
    :type hour_metrics: ~azure.data.tables.models.Metrics
    :param minute_metrics: A summary of request statistics grouped by API in minute aggregates for
     tables.
    :type minute_metrics: ~azure.data.tables.models.Metrics
    :param cors: The set of CORS rules.
    :type cors: list[~azure.data.tables.models.CorsRule]
    """

    _attribute_map = {
        'logging': {'key': 'Logging', 'type': 'Logging'},
        'hour_metrics': {'key': 'HourMetrics', 'type': 'Metrics'},
        'minute_metrics': {'key': 'MinuteMetrics', 'type': 'Metrics'},
        'cors': {'key': 'Cors', 'type': '[CorsRule]', 'xml': {'name': 'Cors', 'wrapped': True, 'itemsName': 'CorsRule'}},
    }
    _xml_map = {
        'name': 'StorageServiceProperties'
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TableServiceProperties, self).__init__(**kwargs)
        self.logging = kwargs.get('logging', None)
        self.hour_metrics = kwargs.get('hour_metrics', None)
        self.minute_metrics = kwargs.get('minute_metrics', None)
        self.cors = kwargs.get('cors', None)


class TableServiceStats(msrest.serialization.Model):
    """Stats for the service.

    :param geo_replication: Geo-Replication information for the Secondary Storage Service.
    :type geo_replication: ~azure.data.tables.models.GeoReplication
    """

    _attribute_map = {
        'geo_replication': {'key': 'GeoReplication', 'type': 'GeoReplication'},
    }
    _xml_map = {
        'name': 'StorageServiceStats'
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TableServiceStats, self).__init__(**kwargs)
        self.geo_replication = kwargs.get('geo_replication', None)
