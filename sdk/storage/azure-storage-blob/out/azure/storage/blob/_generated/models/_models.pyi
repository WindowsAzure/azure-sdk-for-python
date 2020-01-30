# Stubs for azure.storage.blob._generated.models._models (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from azure.core.exceptions import HttpResponseError
from msrest.serialization import Model
from typing import Any

class AccessPolicy(Model):
    start: Any = ...
    expiry: Any = ...
    permission: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class AppendPositionAccessConditions(Model):
    max_size: Any = ...
    append_position: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BlobFlatListSegment(Model):
    blob_items: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BlobHierarchyListSegment(Model):
    blob_prefixes: Any = ...
    blob_items: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BlobHTTPHeaders(Model):
    blob_cache_control: Any = ...
    blob_content_type: Any = ...
    blob_content_md5: Any = ...
    blob_content_encoding: Any = ...
    blob_content_language: Any = ...
    blob_content_disposition: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BlobItem(Model):
    name: Any = ...
    deleted: Any = ...
    snapshot: Any = ...
    properties: Any = ...
    metadata: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BlobMetadata(Model):
    additional_properties: Any = ...
    encrypted: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BlobPrefix(Model):
    name: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BlobProperties(Model):
    creation_time: Any = ...
    last_modified: Any = ...
    etag: Any = ...
    content_length: Any = ...
    content_type: Any = ...
    content_encoding: Any = ...
    content_language: Any = ...
    content_md5: Any = ...
    content_disposition: Any = ...
    cache_control: Any = ...
    blob_sequence_number: Any = ...
    blob_type: Any = ...
    lease_status: Any = ...
    lease_state: Any = ...
    lease_duration: Any = ...
    copy_id: Any = ...
    copy_status: Any = ...
    copy_source: Any = ...
    copy_progress: Any = ...
    copy_completion_time: Any = ...
    copy_status_description: Any = ...
    server_encrypted: Any = ...
    incremental_copy: Any = ...
    destination_snapshot: Any = ...
    deleted_time: Any = ...
    remaining_retention_days: Any = ...
    access_tier: Any = ...
    access_tier_inferred: Any = ...
    archive_status: Any = ...
    customer_provided_key_sha256: Any = ...
    access_tier_change_time: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class Block(Model):
    name: Any = ...
    size: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BlockList(Model):
    committed_blocks: Any = ...
    uncommitted_blocks: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class BlockLookupList(Model):
    committed: Any = ...
    uncommitted: Any = ...
    latest: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class ClearRange(Model):
    start: Any = ...
    end: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class ContainerItem(Model):
    name: Any = ...
    properties: Any = ...
    metadata: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class ContainerProperties(Model):
    last_modified: Any = ...
    etag: Any = ...
    lease_status: Any = ...
    lease_state: Any = ...
    lease_duration: Any = ...
    public_access: Any = ...
    has_immutability_policy: Any = ...
    has_legal_hold: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CorsRule(Model):
    allowed_origins: Any = ...
    allowed_methods: Any = ...
    allowed_headers: Any = ...
    exposed_headers: Any = ...
    max_age_in_seconds: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class CpkInfo(Model):
    encryption_key: Any = ...
    encryption_key_sha256: Any = ...
    encryption_algorithm: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DataLakeStorageError(Model):
    error: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DataLakeStorageErrorException(HttpResponseError):
    error: Any = ...
    def __init__(self, response: Any, deserialize: Any, *args: Any) -> None: ...

class DataLakeStorageErrorError(Model):
    code: Any = ...
    message: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class DirectoryHttpHeaders(Model):
    cache_control: Any = ...
    content_type: Any = ...
    content_encoding: Any = ...
    content_language: Any = ...
    content_disposition: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class GeoReplication(Model):
    status: Any = ...
    last_sync_time: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class KeyInfo(Model):
    start: Any = ...
    expiry: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class LeaseAccessConditions(Model):
    lease_id: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class ListBlobsFlatSegmentResponse(Model):
    service_endpoint: Any = ...
    container_name: Any = ...
    prefix: Any = ...
    marker: Any = ...
    max_results: Any = ...
    segment: Any = ...
    next_marker: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class ListBlobsHierarchySegmentResponse(Model):
    service_endpoint: Any = ...
    container_name: Any = ...
    prefix: Any = ...
    marker: Any = ...
    max_results: Any = ...
    delimiter: Any = ...
    segment: Any = ...
    next_marker: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class ListContainersSegmentResponse(Model):
    service_endpoint: Any = ...
    prefix: Any = ...
    marker: Any = ...
    max_results: Any = ...
    container_items: Any = ...
    next_marker: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class Logging(Model):
    version: Any = ...
    delete: Any = ...
    read: Any = ...
    write: Any = ...
    retention_policy: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class Metrics(Model):
    version: Any = ...
    enabled: Any = ...
    include_apis: Any = ...
    retention_policy: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class ModifiedAccessConditions(Model):
    if_modified_since: Any = ...
    if_unmodified_since: Any = ...
    if_match: Any = ...
    if_none_match: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class PageList(Model):
    page_range: Any = ...
    clear_range: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class PageRange(Model):
    start: Any = ...
    end: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class RetentionPolicy(Model):
    enabled: Any = ...
    days: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SequenceNumberAccessConditions(Model):
    if_sequence_number_less_than_or_equal_to: Any = ...
    if_sequence_number_less_than: Any = ...
    if_sequence_number_equal_to: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SignedIdentifier(Model):
    id: Any = ...
    access_policy: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class SourceModifiedAccessConditions(Model):
    source_if_modified_since: Any = ...
    source_if_unmodified_since: Any = ...
    source_if_match: Any = ...
    source_if_none_match: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StaticWebsite(Model):
    enabled: Any = ...
    index_document: Any = ...
    error_document404_path: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageError(Model):
    message: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageErrorException(HttpResponseError):
    error: Any = ...
    def __init__(self, response: Any, deserialize: Any, *args: Any) -> None: ...

class StorageServiceProperties(Model):
    logging: Any = ...
    hour_metrics: Any = ...
    minute_metrics: Any = ...
    cors: Any = ...
    default_service_version: Any = ...
    delete_retention_policy: Any = ...
    static_website: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class StorageServiceStats(Model):
    geo_replication: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...

class UserDelegationKey(Model):
    signed_oid: Any = ...
    signed_tid: Any = ...
    signed_start: Any = ...
    signed_expiry: Any = ...
    signed_service: Any = ...
    signed_version: Any = ...
    value: Any = ...
    def __init__(self, **kwargs: Any) -> None: ...
