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


class ErrorType(str, Enum):

    unknown_token = "UnknownToken"
    repeated_token = "RepeatedToken"


class ErrorCode(str, Enum):

    none = "None"
    server_error = "ServerError"
    invalid_request = "InvalidRequest"
    rate_limit_exceeded = "RateLimitExceeded"
    invalid_authorization = "InvalidAuthorization"
    insufficient_authorization = "InsufficientAuthorization"


class ErrorSubCode(str, Enum):

    unexpected_error = "UnexpectedError"
    resource_error = "ResourceError"
    not_implemented = "NotImplemented"
    parameter_missing = "ParameterMissing"
    parameter_invalid_value = "ParameterInvalidValue"
    http_not_allowed = "HttpNotAllowed"
    blocked = "Blocked"
    authorization_missing = "AuthorizationMissing"
    authorization_redundancy = "AuthorizationRedundancy"
    authorization_disabled = "AuthorizationDisabled"
    authorization_expired = "AuthorizationExpired"


class ActionType(str, Enum):

    edit = "Edit"
    load = "Load"
