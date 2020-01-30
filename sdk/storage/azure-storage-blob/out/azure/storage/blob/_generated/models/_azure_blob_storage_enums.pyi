# Stubs for azure.storage.blob._generated.models._azure_blob_storage_enums (Python 3)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from enum import Enum

class PublicAccessType(str, Enum):
    container: str = ...
    blob: str = ...

class CopyStatusType(str, Enum):
    pending: str = ...
    success: str = ...
    aborted: str = ...
    failed: str = ...

class LeaseDurationType(str, Enum):
    infinite: str = ...
    fixed: str = ...

class LeaseStateType(str, Enum):
    available: str = ...
    leased: str = ...
    expired: str = ...
    breaking: str = ...
    broken: str = ...

class LeaseStatusType(str, Enum):
    locked: str = ...
    unlocked: str = ...

class AccessTier(str, Enum):
    p4: str = ...
    p6: str = ...
    p10: str = ...
    p15: str = ...
    p20: str = ...
    p30: str = ...
    p40: str = ...
    p50: str = ...
    p60: str = ...
    p70: str = ...
    p80: str = ...
    hot: str = ...
    cool: str = ...
    archive: str = ...

class ArchiveStatus(str, Enum):
    rehydrate_pending_to_hot: str = ...
    rehydrate_pending_to_cool: str = ...

class BlobType(str, Enum):
    block_blob: str = ...
    page_blob: str = ...
    append_blob: str = ...

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
    authorization_source_ip_mismatch: str = ...
    authorization_protocol_mismatch: str = ...
    authorization_permission_mismatch: str = ...
    authorization_service_mismatch: str = ...
    authorization_resource_type_mismatch: str = ...

class GeoReplicationStatusType(str, Enum):
    live: str = ...
    bootstrap: str = ...
    unavailable: str = ...

class AccessTierRequired(str, Enum):
    p4: str = ...
    p6: str = ...
    p10: str = ...
    p15: str = ...
    p20: str = ...
    p30: str = ...
    p40: str = ...
    p50: str = ...
    p60: str = ...
    p70: str = ...
    p80: str = ...
    hot: str = ...
    cool: str = ...
    archive: str = ...

class AccessTierOptional(str, Enum):
    p4: str = ...
    p6: str = ...
    p10: str = ...
    p15: str = ...
    p20: str = ...
    p30: str = ...
    p40: str = ...
    p50: str = ...
    p60: str = ...
    p70: str = ...
    p80: str = ...
    hot: str = ...
    cool: str = ...
    archive: str = ...

class PremiumPageBlobAccessTier(str, Enum):
    p4: str = ...
    p6: str = ...
    p10: str = ...
    p15: str = ...
    p20: str = ...
    p30: str = ...
    p40: str = ...
    p50: str = ...
    p60: str = ...
    p70: str = ...
    p80: str = ...

class RehydratePriority(str, Enum):
    high: str = ...
    standard: str = ...

class BlockListType(str, Enum):
    committed: str = ...
    uncommitted: str = ...
    all: str = ...

class DeleteSnapshotsOptionType(str, Enum):
    include: str = ...
    only: str = ...

class EncryptionAlgorithmType(str, Enum):
    aes256: str = ...

class ListBlobsIncludeItem(str, Enum):
    copy: str = ...
    deleted: str = ...
    metadata: str = ...
    snapshots: str = ...
    uncommittedblobs: str = ...

class ListContainersIncludeType(str, Enum):
    metadata: str = ...

class PathRenameMode(str, Enum):
    legacy: str = ...
    posix: str = ...

class SequenceNumberActionType(str, Enum):
    max: str = ...
    update: str = ...
    increment: str = ...

class SkuName(str, Enum):
    standard_lrs: str = ...
    standard_grs: str = ...
    standard_ragrs: str = ...
    standard_zrs: str = ...
    premium_lrs: str = ...

class AccountKind(str, Enum):
    storage: str = ...
    blob_storage: str = ...
    storage_v2: str = ...

class SyncCopyStatusType(str, Enum):
    success: str = ...
