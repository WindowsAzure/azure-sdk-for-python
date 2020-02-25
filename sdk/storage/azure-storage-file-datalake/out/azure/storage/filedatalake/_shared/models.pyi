# Stubs for azure.storage.filedatalake._shared.models (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from enum import Enum
from typing import Any, Optional

def get_enum_value(value: Any): ...

class StorageErrorCode(str, Enum):
    account_already_exists: str = ...
    account_being_created: str = ...
    account_is_disabled: str = ...
    authentication_failed: str = ...
    authorization_failure: str = ...
    condition_headers_not_supported: str = ...
    condition_not_met: str = ...
    empty_metadata_key: str = ...
    insufficient_account_permissions: str = ...
    internal_error: str = ...
    invalid_authentication_info: str = ...
    invalid_header_value: str = ...
    invalid_http_verb: str = ...
    invalid_input: str = ...
    invalid_md5: str = ...
    invalid_metadata: str = ...
    invalid_query_parameter_value: str = ...
    invalid_range: str = ...
    invalid_resource_name: str = ...
    invalid_uri: str = ...
    invalid_xml_document: str = ...
    invalid_xml_node_value: str = ...
    md5_mismatch: str = ...
    metadata_too_large: str = ...
    missing_content_length_header: str = ...
    missing_required_query_parameter: str = ...
    missing_required_header: str = ...
    missing_required_xml_node: str = ...
    multiple_condition_headers_not_supported: str = ...
    operation_timed_out: str = ...
    out_of_range_input: str = ...
    out_of_range_query_parameter_value: str = ...
    request_body_too_large: str = ...
    resource_type_mismatch: str = ...
    request_url_failed_to_parse: str = ...
    resource_already_exists: str = ...
    resource_not_found: str = ...
    server_busy: str = ...
    unsupported_header: str = ...
    unsupported_xml_node: str = ...
    unsupported_query_parameter: str = ...
    unsupported_http_verb: str = ...
    append_position_condition_not_met: str = ...
    blob_already_exists: str = ...
    blob_not_found: str = ...
    blob_overwritten: str = ...
    blob_tier_inadequate_for_content_length: str = ...
    block_count_exceeds_limit: str = ...
    block_list_too_long: str = ...
    cannot_change_to_lower_tier: str = ...
    cannot_verify_copy_source: str = ...
    container_already_exists: str = ...
    container_being_deleted: str = ...
    container_disabled: str = ...
    container_not_found: str = ...
    content_length_larger_than_tier_limit: str = ...
    copy_across_accounts_not_supported: str = ...
    copy_id_mismatch: str = ...
    feature_version_mismatch: str = ...
    incremental_copy_blob_mismatch: str = ...
    incremental_copy_of_eralier_version_snapshot_not_allowed: str = ...
    incremental_copy_source_must_be_snapshot: str = ...
    infinite_lease_duration_required: str = ...
    invalid_blob_or_block: str = ...
    invalid_blob_tier: str = ...
    invalid_blob_type: str = ...
    invalid_block_id: str = ...
    invalid_block_list: str = ...
    invalid_operation: str = ...
    invalid_page_range: str = ...
    invalid_source_blob_type: str = ...
    invalid_source_blob_url: str = ...
    invalid_version_for_page_blob_operation: str = ...
    lease_already_present: str = ...
    lease_already_broken: str = ...
    lease_id_mismatch_with_blob_operation: str = ...
    lease_id_mismatch_with_container_operation: str = ...
    lease_id_mismatch_with_lease_operation: str = ...
    lease_id_missing: str = ...
    lease_is_breaking_and_cannot_be_acquired: str = ...
    lease_is_breaking_and_cannot_be_changed: str = ...
    lease_is_broken_and_cannot_be_renewed: str = ...
    lease_lost: str = ...
    lease_not_present_with_blob_operation: str = ...
    lease_not_present_with_container_operation: str = ...
    lease_not_present_with_lease_operation: str = ...
    max_blob_size_condition_not_met: str = ...
    no_pending_copy_operation: str = ...
    operation_not_allowed_on_incremental_copy_blob: str = ...
    pending_copy_operation: str = ...
    previous_snapshot_cannot_be_newer: str = ...
    previous_snapshot_not_found: str = ...
    previous_snapshot_operation_not_supported: str = ...
    sequence_number_condition_not_met: str = ...
    sequence_number_increment_too_large: str = ...
    snapshot_count_exceeded: str = ...
    snaphot_operation_rate_exceeded: str = ...
    snapshots_present: str = ...
    source_condition_not_met: str = ...
    system_in_use: str = ...
    target_condition_not_met: str = ...
    unauthorized_blob_overwrite: str = ...
    blob_being_rehydrated: str = ...
    blob_archived: str = ...
    blob_not_archived: str = ...
    invalid_marker: str = ...
    message_not_found: str = ...
    message_too_large: str = ...
    pop_receipt_mismatch: str = ...
    queue_already_exists: str = ...
    queue_being_deleted: str = ...
    queue_disabled: str = ...
    queue_not_empty: str = ...
    queue_not_found: str = ...
    cannot_delete_file_or_directory: str = ...
    client_cache_flush_delay: str = ...
    delete_pending: str = ...
    directory_not_empty: str = ...
    file_lock_conflict: str = ...
    invalid_file_or_directory_path_name: str = ...
    parent_not_found: str = ...
    read_only_attribute: str = ...
    share_already_exists: str = ...
    share_being_deleted: str = ...
    share_disabled: str = ...
    share_not_found: str = ...
    sharing_violation: str = ...
    share_snapshot_in_progress: str = ...
    share_snapshot_count_exceeded: str = ...
    share_snapshot_operation_not_supported: str = ...
    share_has_snapshots: str = ...
    container_quota_downgrade_not_allowed: str = ...
    content_length_must_be_zero: str = ...
    path_already_exists: str = ...
    invalid_flush_position: str = ...
    invalid_property_name: str = ...
    invalid_source_uri: str = ...
    unsupported_rest_version: str = ...
    file_system_not_found: str = ...
    path_not_found: str = ...
    rename_destination_parent_path_not_found: str = ...
    source_path_not_found: str = ...
    destination_path_is_being_deleted: str = ...
    file_system_already_exists: str = ...
    file_system_being_deleted: str = ...
    invalid_destination_path: str = ...
    invalid_rename_source_path: str = ...
    invalid_source_or_destination_resource_type: str = ...
    lease_is_already_broken: str = ...
    lease_name_mismatch: str = ...
    path_conflict: str = ...
    source_path_is_being_deleted: str = ...

class DictMixin:
    def __setitem__(self, key: Any, item: Any) -> None: ...
    def __getitem__(self, key: Any): ...
    def __len__(self): ...
    def __delitem__(self, key: Any) -> None: ...
    def __eq__(self, other: Any): ...
    def __ne__(self, other: Any): ...
    def has_key(self, k: Any): ...
    def update(self, *args: Any, **kwargs: Any): ...
    def keys(self): ...
    def values(self): ...
    def items(self): ...
    def get(self, key: Any, default: Optional[Any] = ...): ...

class LocationMode:
    PRIMARY: str = ...
    SECONDARY: str = ...

class ResourceTypes:
    service: Any = ...
    container: Any = ...
    object: Any = ...
    def __init__(self, service: bool = ..., container: bool = ..., object: bool = ...) -> None: ...
    @classmethod
    def from_string(cls, string: Any): ...

class AccountSasPermissions:
    read: Any = ...
    write: Any = ...
    delete: Any = ...
    list: Any = ...
    add: Any = ...
    create: Any = ...
    update: Any = ...
    process: Any = ...
    def __init__(self, read: bool = ..., write: bool = ..., delete: bool = ..., list: bool = ..., add: bool = ..., create: bool = ..., update: bool = ..., process: bool = ...) -> None: ...
    @classmethod
    def from_string(cls, permission: Any): ...

class Services:
    blob: Any = ...
    queue: Any = ...
    file: Any = ...
    def __init__(self, blob: bool = ..., queue: bool = ..., file: bool = ...) -> None: ...
    @classmethod
    def from_string(cls, string: Any): ...

class UserDelegationKey:
    signed_oid: Any = ...
    signed_tid: Any = ...
    signed_start: Any = ...
    signed_expiry: Any = ...
    signed_service: Any = ...
    signed_version: Any = ...
    value: Any = ...
    def __init__(self) -> None: ...
