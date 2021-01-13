# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class DocumentSentimentValue(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Predicted sentiment for document (Negative, Neutral, Positive, or Mixed).
    """

    POSITIVE = "positive"
    NEUTRAL = "neutral"
    NEGATIVE = "negative"
    MIXED = "mixed"

class ErrorCodeValue(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Error code.
    """

    INVALID_REQUEST = "InvalidRequest"
    INVALID_ARGUMENT = "InvalidArgument"
    INTERNAL_SERVER_ERROR = "InternalServerError"
    SERVICE_UNAVAILABLE = "ServiceUnavailable"
    NOT_FOUND = "NotFound"

class InnerErrorCodeValue(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Error code.
    """

    INVALID_PARAMETER_VALUE = "InvalidParameterValue"
    INVALID_REQUEST_BODY_FORMAT = "InvalidRequestBodyFormat"
    EMPTY_REQUEST = "EmptyRequest"
    MISSING_INPUT_RECORDS = "MissingInputRecords"
    INVALID_DOCUMENT = "InvalidDocument"
    MODEL_VERSION_INCORRECT = "ModelVersionIncorrect"
    INVALID_DOCUMENT_BATCH = "InvalidDocumentBatch"
    UNSUPPORTED_LANGUAGE_CODE = "UnsupportedLanguageCode"
    INVALID_COUNTRY_HINT = "InvalidCountryHint"

class PiiTaskParametersDomain(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    PHI = "phi"
    NONE = "none"

class SentenceSentimentValue(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The predicted Sentiment for the sentence.
    """

    POSITIVE = "positive"
    NEUTRAL = "neutral"
    NEGATIVE = "negative"

class State(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    NOT_STARTED = "notStarted"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    CANCELLING = "cancelling"
    PARTIALLY_COMPLETED = "partiallyCompleted"

class StringIndexType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    TEXT_ELEMENTS_V8 = "TextElements_v8"  #: Returned offset and length values will correspond to TextElements (Graphemes and Grapheme clusters) confirming to the Unicode 8.0.0 standard. Use this option if your application is written in .Net Framework or .Net Core and you will be using StringInfo.
    UNICODE_CODE_POINT = "UnicodeCodePoint"  #: Returned offset and length values will correspond to Unicode code points. Use this option if your application is written in a language that support Unicode, for example Python.
    UTF16_CODE_UNIT = "Utf16CodeUnit"  #: Returned offset and length values will correspond to UTF-16 code units. Use this option if your application is written in a language that support Unicode, for example Java, JavaScript.

class StringIndexTypeResponse(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    TEXT_ELEMENTS_V8 = "TextElements_v8"  #: Returned offset and length values will correspond to TextElements (Graphemes and Grapheme clusters) confirming to the Unicode 8.0.0 standard. Use this option if your application is written in .Net Framework or .Net Core and you will be using StringInfo.
    UNICODE_CODE_POINT = "UnicodeCodePoint"  #: Returned offset and length values will correspond to Unicode code points. Use this option if your application is written in a language that support Unicode, for example Python.
    UTF16_CODE_UNIT = "Utf16CodeUnit"  #: Returned offset and length values will correspond to UTF-16 code units. Use this option if your application is written in a language that support Unicode, for example Java, JavaScript.

class TargetRelationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type related to the target.
    """

    ASSESSMENT = "assessment"
    TARGET = "target"

class TokenSentimentValue(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Targeted sentiment in the sentence.
    """

    POSITIVE = "positive"
    MIXED = "mixed"
    NEGATIVE = "negative"

class WarningCodeValue(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Error code.
    """

    LONG_WORDS_IN_DOCUMENT = "LongWordsInDocument"
    DOCUMENT_TRUNCATED = "DocumentTruncated"
