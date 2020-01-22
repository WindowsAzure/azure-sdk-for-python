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


class ErrorCodeValue(str, Enum):

    invalid_request = "invalidRequest"
    invalid_argument = "invalidArgument"
    internal_server_error = "internalServerError"
    service_unavailable = "serviceUnavailable"


class InnerErrorCodeValue(str, Enum):

    invalid_parameter_value = "invalidParameterValue"
    invalid_request_body_format = "invalidRequestBodyFormat"
    empty_request = "emptyRequest"
    missing_input_records = "missingInputRecords"
    invalid_document = "invalidDocument"
    model_version_incorrect = "modelVersionIncorrect"
    invalid_document_batch = "invalidDocumentBatch"
    unsupported_language_code = "unsupportedLanguageCode"
    invalid_country_hint = "invalidCountryHint"


class DocumentSentimentValue(str, Enum):

    positive = "positive"
    neutral = "neutral"
    negative = "negative"
    mixed = "mixed"


class SentenceSentimentValue(str, Enum):

    positive = "positive"
    neutral = "neutral"
    negative = "negative"
