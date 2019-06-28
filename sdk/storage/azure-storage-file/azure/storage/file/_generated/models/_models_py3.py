# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model
from azure.core import HttpResponseError


class AccessPolicy(Model):
    """An Access policy.

    :param start: The date-time the policy is active.
    :type start: datetime
    :param expiry: The date-time the policy expires.
    :type expiry: datetime
    :param permission: The permissions for the ACL policy.
    :type permission: str
    """

    _attribute_map = {
        'start': {'key': 'Start', 'type': 'str', 'xml': {'name': 'Start'}},
        'expiry': {'key': 'Expiry', 'type': 'str', 'xml': {'name': 'Expiry'}},
        'permission': {'key': 'Permission', 'type': 'str', 'xml': {'name': 'Permission'}},
    }
    _xml_map = {
    }


    def __init__(self, *, start=None, expiry=None, permission: str=None, **kwargs) -> None:
        super(AccessPolicy, self).__init__(**kwargs)
        self.start = start
        self.expiry = expiry
        self.permission = permission


class CorsRule(Model):
    """CORS is an HTTP feature that enables a web application running under one
    domain to access resources in another domain. Web browsers implement a
    security restriction known as same-origin policy that prevents a web page
    from calling APIs in a different domain; CORS provides a secure way to
    allow one domain (the origin domain) to call APIs in another domain.

    All required parameters must be populated in order to send to Azure.

    :param allowed_origins: Required. The origin domains that are permitted to
     make a request against the storage service via CORS. The origin domain is
     the domain from which the request originates. Note that the origin must be
     an exact case-sensitive match with the origin that the user age sends to
     the service. You can also use the wildcard character '*' to allow all
     origin domains to make requests via CORS.
    :type allowed_origins: str
    :param allowed_methods: Required. The methods (HTTP request verbs) that
     the origin domain may use for a CORS request. (comma separated)
    :type allowed_methods: str
    :param allowed_headers: Required. The request headers that the origin
     domain may specify on the CORS request.
    :type allowed_headers: str
    :param exposed_headers: Required. The response headers that may be sent in
     the response to the CORS request and exposed by the browser to the request
     issuer.
    :type exposed_headers: str
    :param max_age_in_seconds: Required. The maximum amount time that a
     browser should cache the preflight OPTIONS request.
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
    }

    def __init__(self, *, allowed_origins: str, allowed_methods: str, allowed_headers: str, exposed_headers: str, max_age_in_seconds: int, **kwargs) -> None:
        super(CorsRule, self).__init__(**kwargs)
        self.allowed_origins = allowed_origins
        self.allowed_methods = allowed_methods
        self.allowed_headers = allowed_headers
        self.exposed_headers = exposed_headers
        self.max_age_in_seconds = max_age_in_seconds


class DirectoryItem(Model):
    """A listed directory item.

    All required parameters must be populated in order to send to Azure.

    :param name: Required.
    :type name: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str', 'xml': {'name': 'Name'}},
    }
    _xml_map = {
    }

    def __init__(self, *, name: str, **kwargs) -> None:
        super(DirectoryItem, self).__init__(**kwargs)
        self.name = name


class FileHTTPHeaders(Model):
    """Additional parameters for a set of operations, such as: File_create,
    File_set_http_headers.

    :param file_content_type: Sets the MIME content type of the file. The
     default type is 'application/octet-stream'.
    :type file_content_type: str
    :param file_content_encoding: Specifies which content encodings have been
     applied to the file.
    :type file_content_encoding: str
    :param file_content_language: Specifies the natural languages used by this
     resource.
    :type file_content_language: str
    :param file_cache_control: Sets the file's cache control. The File service
     stores this value but does not use or modify it.
    :type file_cache_control: str
    :param file_content_md5: Sets the file's MD5 hash.
    :type file_content_md5: bytearray
    :param file_content_disposition: Sets the file's Content-Disposition
     header.
    :type file_content_disposition: str
    """

    _attribute_map = {
        'file_cache_control': {'key': '', 'type': 'str', 'xml': {'name': 'file_cache_control'}},
        'file_content_type': {'key': '', 'type': 'str', 'xml': {'name': 'file_content_type'}},
        'file_content_md5': {'key': '', 'type': 'bytearray', 'xml': {'name': 'file_content_md5'}},
        'file_content_encoding': {'key': '', 'type': 'str', 'xml': {'name': 'file_content_encoding'}},
        'file_content_language': {'key': '', 'type': 'str', 'xml': {'name': 'file_content_language'}},
        'file_content_disposition': {'key': '', 'type': 'str', 'xml': {'name': 'file_content_disposition'}},
    }
    _xml_map = {
    }

    def __init__(self, *, file_content_type: str=None, file_content_encoding: str=None, file_content_language: str=None, file_cache_control: str=None, file_content_md5: bytearray=None, file_content_disposition: str=None, **kwargs) -> None:
        super(FileHTTPHeaders, self).__init__(**kwargs)
        self.file_content_type = file_content_type
        self.file_content_encoding = file_content_encoding
        self.file_content_language = file_content_language
        self.file_cache_control = file_cache_control
        self.file_content_md5 = file_content_md5
        self.file_content_disposition = file_content_disposition


class FileItem(Model):
    """A listed file item.

    All required parameters must be populated in order to send to Azure.

    :param name: Required.
    :type name: str
    :param properties: Required.
    :type properties: ~file.models.FileProperty
    """

    _validation = {
        'name': {'required': True},
        'properties': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str', 'xml': {'name': 'Name'}},
        'properties': {'key': 'Properties', 'type': 'FileProperty', 'xml': {'name': 'Properties'}},
    }
    _xml_map = {
        'name': 'File'
    }

    def __init__(self, *, name: str, properties, **kwargs) -> None:
        super(FileItem, self).__init__(**kwargs)
        self.name = name
        self.properties = properties


class FileProperty(Model):
    """File properties.

    All required parameters must be populated in order to send to Azure.

    :param content_length: Required. Content length of the file. This value
     may not be up-to-date since an SMB client may have modified the file
     locally. The value of Content-Length may not reflect that fact until the
     handle is closed or the op-lock is broken. To retrieve current property
     values, call Get File Properties.
    :type content_length: long
    """

    _validation = {
        'content_length': {'required': True},
    }

    _attribute_map = {
        'content_length': {'key': 'Content-Length', 'type': 'long', 'xml': {'name': 'Content-Length'}},
    }
    _xml_map = {
        'name': 'Properties'
    }

    def __init__(self, *, content_length: int, **kwargs) -> None:
        super(FileProperty, self).__init__(**kwargs)
        self.content_length = content_length


class FilesAndDirectoriesListSegment(Model):
    """Abstract for entries that can be listed from Directory.

    All required parameters must be populated in order to send to Azure.

    :param directory_items: Required.
    :type directory_items: list[~file.models.DirectoryItem]
    :param file_items: Required.
    :type file_items: list[~file.models.FileItem]
    """

    _validation = {
        'directory_items': {'required': True},
        'file_items': {'required': True},
    }

    _attribute_map = {
        'handle_list': {'key': 'HandleList', 'type': '[HandleItem]', 'xml': {'name': 'Entries', 'itemsName': 'Entries', 'wrapped': True}},
        'next_marker': {'key': 'NextMarker', 'type': 'str', 'xml': {'name': 'NextMarker'}},
    }
    _xml_map = {
        'name': 'Entries'
    }

    def __init__(self, *, directory_items, file_items, **kwargs) -> None:
        super(FilesAndDirectoriesListSegment, self).__init__(**kwargs)
        self.directory_items = directory_items
        self.file_items = file_items


class HandleItem(Model):
    """A listed Azure Storage handle item.

    All required parameters must be populated in order to send to Azure.

    :param handle_id: Required. XSMB service handle ID
    :type handle_id: str
    :param path: Required. File or directory name including full path starting
     from share root
    :type path: str
    :param file_id: Required. FileId uniquely identifies the file or
     directory.
    :type file_id: str
    :param parent_id: ParentId uniquely identifies the parent directory of the
     object.
    :type parent_id: str
    :param session_id: Required. SMB session ID in context of which the file
     handle was opened
    :type session_id: str
    :param client_ip: Required. Client IP that opened the handle
    :type client_ip: str
    :param open_time: Required. Time when the session that previously opened
     the handle has last been reconnected. (UTC)
    :type open_time: datetime
    :param last_reconnect_time: Time handle was last connected to (UTC)
    :type last_reconnect_time: datetime
    """

    _validation = {
        'handle_id': {'required': True},
        'path': {'required': True},
        'file_id': {'required': True},
        'session_id': {'required': True},
        'client_ip': {'required': True},
        'open_time': {'required': True},
    }

    _attribute_map = {
        'handle_id': {'key': 'HandleId', 'type': 'str', 'xml': {'name': 'HandleId'}},
        'path': {'key': 'Path', 'type': 'str', 'xml': {'name': 'Path'}},
        'file_id': {'key': 'FileId', 'type': 'str', 'xml': {'name': 'FileId'}},
        'parent_id': {'key': 'ParentId', 'type': 'str', 'xml': {'name': 'ParentId'}},
        'session_id': {'key': 'SessionId', 'type': 'str', 'xml': {'name': 'SessionId'}},
        'client_ip': {'key': 'ClientIp', 'type': 'str', 'xml': {'name': 'ClientIp'}},
        'open_time': {'key': 'OpenTime', 'type': 'rfc-1123', 'xml': {'name': 'OpenTime'}},
        'last_reconnect_time': {'key': 'LastReconnectTime', 'type': 'rfc-1123', 'xml': {'name': 'LastReconnectTime'}},
    }
    _xml_map = {
        'name': 'Handle'
    }

    def __init__(self, *, handle_id: str, path: str, file_id: str, session_id: str, client_ip: str, open_time, parent_id: str=None, last_reconnect_time=None, **kwargs) -> None:
        super(HandleItem, self).__init__(**kwargs)
        self.handle_id = handle_id
        self.path = path
        self.file_id = file_id
        self.parent_id = parent_id
        self.session_id = session_id
        self.client_ip = client_ip
        self.open_time = open_time
        self.last_reconnect_time = last_reconnect_time


class ListFilesAndDirectoriesSegmentResponse(Model):
    """An enumeration of directories and files.

    All required parameters must be populated in order to send to Azure.

    :param service_endpoint: Required.
    :type service_endpoint: str
    :param share_name: Required.
    :type share_name: str
    :param share_snapshot:
    :type share_snapshot: str
    :param directory_path: Required.
    :type directory_path: str
    :param prefix: Required.
    :type prefix: str
    :param marker:
    :type marker: str
    :param max_results:
    :type max_results: int
    :param segment: Required.
    :type segment: ~file.models.FilesAndDirectoriesListSegment
    :param next_marker: Required.
    :type next_marker: str
    """

    _validation = {
        'service_endpoint': {'required': True},
        'share_name': {'required': True},
        'directory_path': {'required': True},
        'prefix': {'required': True},
        'segment': {'required': True},
        'next_marker': {'required': True},
    }

    _attribute_map = {
        'service_endpoint': {'key': 'ServiceEndpoint', 'type': 'str', 'xml': {'name': 'ServiceEndpoint', 'attr': True}},
        'share_name': {'key': 'ShareName', 'type': 'str', 'xml': {'name': 'ShareName', 'attr': True}},
        'share_snapshot': {'key': 'ShareSnapshot', 'type': 'str', 'xml': {'name': 'ShareSnapshot'}},
        'directory_path': {'key': 'DirectoryPath', 'type': 'str', 'xml': {'name': 'DirectoryPath'}},
        'prefix': {'key': 'Prefix', 'type': 'str', 'xml': {'name': 'Prefix'}},
        'marker': {'key': 'Marker', 'type': 'str', 'xml': {'name': 'Marker'}},
        'max_results': {'key': 'MaxResults', 'type': 'int', 'xml': {'name': 'MaxResults'}},
        'segment': {'key': 'Segment', 'type': 'FilesAndDirectoriesListSegment', 'xml': {'name': 'Segment'}},
        'next_marker': {'key': 'NextMarker', 'type': 'str', 'xml': {'name': 'NextMarker'}},
    }
    _xml_map = {
        'name': 'EnumerationResults'
    }

    def __init__(self, *, service_endpoint: str, share_name: str, directory_path: str, prefix: str, segment, next_marker: str, share_snapshot: str=None, marker: str=None, max_results: int=None, **kwargs) -> None:
        super(ListFilesAndDirectoriesSegmentResponse, self).__init__(**kwargs)
        self.service_endpoint = service_endpoint
        self.share_name = share_name
        self.share_snapshot = share_snapshot
        self.directory_path = directory_path
        self.prefix = prefix
        self.marker = marker
        self.max_results = max_results
        self.segment = segment
        self.next_marker = next_marker


class ListHandlesResponse(Model):
    """An enumeration of handles.

    All required parameters must be populated in order to send to Azure.

    :param handle_list:
    :type handle_list: list[~file.models.HandleItem]
    :param next_marker: Required.
    :type next_marker: str
    """

    _validation = {
        'next_marker': {'required': True},
    }

    _attribute_map = {
        'handle_list': {'key': 'HandleList', 'type': '[HandleItem]', 'xml': {'name': 'HandleList'}},
        'next_marker': {'key': 'NextMarker', 'type': 'str', 'xml': {'name': 'NextMarker'}},
    }
    _xml_map = {
        'name': 'EnumerationResults'
    }

    def __init__(self, *, next_marker: str, handle_list=None, **kwargs) -> None:
        super(ListHandlesResponse, self).__init__(**kwargs)
        self.handle_list = handle_list
        self.next_marker = next_marker


class ListSharesResponse(Model):
    """An enumeration of shares.

    All required parameters must be populated in order to send to Azure.

    :param service_endpoint: Required.
    :type service_endpoint: str
    :param prefix:
    :type prefix: str
    :param marker:
    :type marker: str
    :param max_results:
    :type max_results: int
    :param share_items:
    :type share_items: list[~file.models.ShareItem]
    :param next_marker: Required.
    :type next_marker: str
    """

    _validation = {
        'service_endpoint': {'required': True},
        'next_marker': {'required': True},
    }

    _attribute_map = {
        'service_endpoint': {'key': 'ServiceEndpoint', 'type': 'str', 'xml': {'name': 'ServiceEndpoint', 'attr': True}},
        'prefix': {'key': 'Prefix', 'type': 'str', 'xml': {'name': 'Prefix'}},
        'marker': {'key': 'Marker', 'type': 'str', 'xml': {'name': 'Marker'}},
        'max_results': {'key': 'MaxResults', 'type': 'int', 'xml': {'name': 'MaxResults'}},
        'share_items': {'key': 'ShareItems', 'type': '[ShareItem]', 'xml': {'name': 'Shares', 'itemsName': 'Shares', 'wrapped': True}},
        'next_marker': {'key': 'NextMarker', 'type': 'str', 'xml': {'name': 'NextMarker'}},
    }
    _xml_map = {
        'name': 'EnumerationResults'
    }

    def __init__(self, *, service_endpoint: str, next_marker: str, prefix: str=None, marker: str=None, max_results: int=None, share_items=None, **kwargs) -> None:
        super(ListSharesResponse, self).__init__(**kwargs)
        self.service_endpoint = service_endpoint
        self.prefix = prefix
        self.marker = marker
        self.max_results = max_results
        self.share_items = share_items
        self.next_marker = next_marker


class Metrics(Model):
    """Storage Analytics metrics for file service.

    All required parameters must be populated in order to send to Azure.

    :param version: Required. The version of Storage Analytics to configure.
    :type version: str
    :param enabled: Required. Indicates whether metrics are enabled for the
     File service.
    :type enabled: bool
    :param include_apis: Indicates whether metrics should generate summary
     statistics for called API operations.
    :type include_apis: bool
    :param retention_policy:
    :type retention_policy: ~file.models.RetentionPolicy
    """

    _validation = {
        'version': {'required': True},
        'enabled': {'required': True},
    }

    _attribute_map = {
        'version': {'key': 'Version', 'type': 'str', 'xml': {'name': 'Version'}},
        'enabled': {'key': 'Enabled', 'type': 'bool', 'xml': {'name': 'Enabled'}},
        'include_apis': {'key': 'IncludeAPIs', 'type': 'bool', 'xml': {'name': 'IncludeAPIs'}},
        'retention_policy': {'key': 'RetentionPolicy', 'type': 'RetentionPolicy', 'xml': {'name': 'RetentionPolicy'}},
    }
    _xml_map = {
    }

    def __init__(self, *, version: str, enabled: bool, include_apis: bool=None, retention_policy=None, **kwargs) -> None:
        super(Metrics, self).__init__(**kwargs)
        self.version = version
        self.enabled = enabled
        self.include_apis = include_apis
        self.retention_policy = retention_policy


class Range(Model):
    """An Azure Storage file range.

    All required parameters must be populated in order to send to Azure.

    :param start: Required. Start of the range.
    :type start: long
    :param end: Required. End of the range.
    :type end: long
    """

    _validation = {
        'start': {'required': True},
        'end': {'required': True},
    }

    _attribute_map = {
        'start': {'key': 'Start', 'type': 'long', 'xml': {'name': 'Start'}},
        'end': {'key': 'End', 'type': 'long', 'xml': {'name': 'End'}},
    }
    _xml_map = {
        'name': 'Range'
    }

    def __init__(self, *, start: int, end: int, **kwargs) -> None:
        super(Range, self).__init__(**kwargs)
        self.start = start
        self.end = end


class RetentionPolicy(Model):
    """The retention policy.

    All required parameters must be populated in order to send to Azure.

    :param enabled: Required. Indicates whether a retention policy is enabled
     for the File service. If false, metrics data is retained, and the user is
     responsible for deleting it.
    :type enabled: bool
    :param days: Indicates the number of days that metrics data should be
     retained. All data older than this value will be deleted. Metrics data is
     deleted on a best-effort basis after the retention period expires.
    :type days: int
    """

    _validation = {
        'enabled': {'required': True},
        'days': {'maximum': 365, 'minimum': 1},
    }

    _attribute_map = {
        'enabled': {'key': 'Enabled', 'type': 'bool', 'xml': {'name': 'Enabled'}},
        'days': {'key': 'Days', 'type': 'int', 'xml': {'name': 'Days'}},
    }
    _xml_map = {
    }

    def __init__(self, *, enabled: bool, days: int=None, **kwargs) -> None:
        super(RetentionPolicy, self).__init__(**kwargs)
        self.enabled = enabled
        self.days = days


class ShareItem(Model):
    """A listed Azure Storage share item.

    All required parameters must be populated in order to send to Azure.

    :param name: Required.
    :type name: str
    :param snapshot:
    :type snapshot: str
    :param properties: Required.
    :type properties: ~file.models.ShareProperties
    :param metadata:
    :type metadata: dict[str, str]
    """

    _validation = {
        'name': {'required': True},
        'properties': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str', 'xml': {'name': 'Name'}},
        'snapshot': {'key': 'Snapshot', 'type': 'str', 'xml': {'name': 'Snapshot'}},
        'properties': {'key': 'Properties', 'type': 'ShareProperties', 'xml': {'name': 'Properties'}},
        'metadata': {'key': 'Metadata', 'type': '{str}', 'xml': {'name': 'Metadata'}},
    }
    _xml_map = {
        'name': 'Share'
    }

    def __init__(self, *, name: str, properties, snapshot: str=None, metadata=None, **kwargs) -> None:
        super(ShareItem, self).__init__(**kwargs)
        self.name = name
        self.snapshot = snapshot
        self.properties = properties
        self.metadata = metadata


class ShareProperties(Model):
    """Properties of a share.

    All required parameters must be populated in order to send to Azure.

    :param last_modified: Required.
    :type last_modified: datetime
    :param etag: Required.
    :type etag: str
    :param quota: Required.
    :type quota: int
    """

    _validation = {
        'last_modified': {'required': True},
        'etag': {'required': True},
        'quota': {'required': True},
    }

    _attribute_map = {
        'last_modified': {'key': 'Last-Modified', 'type': 'rfc-1123', 'xml': {'name': 'Last-Modified'}},
        'etag': {'key': 'Etag', 'type': 'str', 'xml': {'name': 'Etag'}},
        'quota': {'key': 'Quota', 'type': 'int', 'xml': {'name': 'Quota'}},
    }
    _xml_map = {
        'name': 'Properties'
    }

    def __init__(self, *, last_modified, etag: str, quota: int, **kwargs) -> None:
        super(ShareProperties, self).__init__(**kwargs)
        self.last_modified = last_modified
        self.etag = etag
        self.quota = quota


class ShareStats(Model):
    """Stats for the share.

    All required parameters must be populated in order to send to Azure.

    :param share_usage_bytes: Required. The approximate size of the data
     stored in bytes. Note that this value may not include all recently created
     or recently resized files.
    :type share_usage_bytes: int
    """

    _validation = {
        'share_usage_bytes': {'required': True},
    }

    _attribute_map = {
        'share_usage_bytes': {'key': 'ShareUsageBytes', 'type': 'int', 'xml': {'name': 'ShareUsageBytes'}},
    }
    _xml_map = {
        'name': 'ShareStats
    }

    def __init__(self, *, share_usage_bytes: int, **kwargs) -> None:
        super(ShareStats, self).__init__(**kwargs)
        self.share_usage_bytes = share_usage_bytes


class SignedIdentifier(Model):
    """Signed identifier.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. A unique id.
    :type id: str
    :param access_policy: The access policy.
    :type access_policy: ~file.models.AccessPolicy
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'Id', 'type': 'str', 'xml': {'name': 'Id'}},
        'access_policy': {'key': 'AccessPolicy', 'type': 'AccessPolicy', 'xml': {'name': 'AccessPolicy'}},
    }
    _xml_map = {
    }

    def __init__(self, *, id: str, access_policy=None, **kwargs) -> None:
        super(SignedIdentifier, self).__init__(**kwargs)
        self.id = id
        self.access_policy = access_policy


class StorageError(Model):
    """StorageError.

    :param message:
    :type message: str
    """

    _attribute_map = {
        'message': {'key': 'Message', 'type': 'str', 'xml': {'name': 'Message'}},
    }
    _xml_map = {
    }

    def __init__(self, *, message: str=None, **kwargs) -> None:
        super(StorageError, self).__init__(**kwargs)
        self.message = message


class StorageErrorException(HttpResponseError):
    """Server responsed with exception of type: 'StorageError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, response, deserialize, *args):

      model_name = 'StorageError'
      self.error = deserialize(model_name, response)
      if self.error is None:
          self.error = deserialize.dependencies[model_name]()
      super(StorageErrorException, self).__init__(response=response)


class StorageServiceProperties(Model):
    """Storage service properties.

    :param hour_metrics: A summary of request statistics grouped by API in
     hourly aggregates for files.
    :type hour_metrics: ~file.models.Metrics
    :param minute_metrics: A summary of request statistics grouped by API in
     minute aggregates for files.
    :type minute_metrics: ~file.models.Metrics
    :param cors: The set of CORS rules.
    :type cors: list[~file.models.CorsRule]
    """

    _attribute_map = {
        'hour_metrics': {'key': 'HourMetrics', 'type': 'Metrics', 'xml': {'name': 'HourMetrics'}},
        'minute_metrics': {'key': 'MinuteMetrics', 'type': 'Metrics', 'xml': {'name': 'MinuteMetrics'}},
        'cors': {'key': 'Cors', 'type': '[CorsRule]', 'xml': {'name': 'Cors', 'itemsName': 'CorsRule', 'wrapped': True}},
    }
    _xml_map = {
    }

    def __init__(self, *, hour_metrics=None, minute_metrics=None, cors=None, **kwargs) -> None:
        super(StorageServiceProperties, self).__init__(**kwargs)
        self.hour_metrics = hour_metrics
        self.minute_metrics = minute_metrics
        self.cors = cors
