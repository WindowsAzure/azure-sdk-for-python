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

from enum import Enum


class StorageErrorCode(str, Enum):

    account_already_exists = "AccountAlreadyExists"
    account_being_created = "AccountBeingCreated"
    account_is_disabled = "AccountIsDisabled"
    authentication_failed = "AuthenticationFailed"
    authorization_failure = "AuthorizationFailure"
    condition_headers_not_supported = "ConditionHeadersNotSupported"
    condition_not_met = "ConditionNotMet"
    empty_metadata_key = "EmptyMetadataKey"
    insufficient_account_permissions = "InsufficientAccountPermissions"
    internal_error = "InternalError"
    invalid_authentication_info = "InvalidAuthenticationInfo"
    invalid_header_value = "InvalidHeaderValue"
    invalid_http_verb = "InvalidHttpVerb"
    invalid_input = "InvalidInput"
    invalid_md5 = "InvalidMd5"
    invalid_metadata = "InvalidMetadata"
    invalid_query_parameter_value = "InvalidQueryParameterValue"
    invalid_range = "InvalidRange"
    invalid_resource_name = "InvalidResourceName"
    invalid_uri = "InvalidUri"
    invalid_xml_document = "InvalidXmlDocument"
    invalid_xml_node_value = "InvalidXmlNodeValue"
    md5_mismatch = "Md5Mismatch"
    metadata_too_large = "MetadataTooLarge"
    missing_content_length_header = "MissingContentLengthHeader"
    missing_required_query_parameter = "MissingRequiredQueryParameter"
    missing_required_header = "MissingRequiredHeader"
    missing_required_xml_node = "MissingRequiredXmlNode"
    multiple_condition_headers_not_supported = "MultipleConditionHeadersNotSupported"
    operation_timed_out = "OperationTimedOut"
    out_of_range_input = "OutOfRangeInput"
    out_of_range_query_parameter_value = "OutOfRangeQueryParameterValue"
    request_body_too_large = "RequestBodyTooLarge"
    resource_type_mismatch = "ResourceTypeMismatch"
    request_url_failed_to_parse = "RequestUrlFailedToParse"
    resource_already_exists = "ResourceAlreadyExists"
    resource_not_found = "ResourceNotFound"
    server_busy = "ServerBusy"
    unsupported_header = "UnsupportedHeader"
    unsupported_xml_node = "UnsupportedXmlNode"
    unsupported_query_parameter = "UnsupportedQueryParameter"
    unsupported_http_verb = "UnsupportedHttpVerb"
    invalid_marker = "InvalidMarker"
    message_not_found = "MessageNotFound"
    message_too_large = "MessageTooLarge"
    pop_receipt_mismatch = "PopReceiptMismatch"
    queue_already_exists = "QueueAlreadyExists"
    queue_being_deleted = "QueueBeingDeleted"
    queue_disabled = "QueueDisabled"
    queue_not_empty = "QueueNotEmpty"
    queue_not_found = "QueueNotFound"


class GeoReplicationStatusType(str, Enum):

    live = "live"
    bootstrap = "bootstrap"
    unavailable = "unavailable"


class ListQueuesIncludeType(str, Enum):

    metadata = "metadata"
