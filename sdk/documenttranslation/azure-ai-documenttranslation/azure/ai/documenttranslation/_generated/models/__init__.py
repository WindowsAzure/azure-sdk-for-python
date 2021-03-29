# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import BatchRequest
    from ._models_py3 import BatchStatusDetail
    from ._models_py3 import BatchStatusResponse
    from ._models_py3 import BatchSubmissionRequest
    from ._models_py3 import DocumentFilter
    from ._models_py3 import DocumentStatusDetail
    from ._models_py3 import DocumentStatusResponse
    from ._models_py3 import ErrorResponseV2
    from ._models_py3 import ErrorV2
    from ._models_py3 import FileFormat
    from ._models_py3 import FileFormatListResult
    from ._models_py3 import Glossary
    from ._models_py3 import InnerErrorV2
    from ._models_py3 import SourceInput
    from ._models_py3 import StatusSummary
    from ._models_py3 import StorageSourceListResult
    from ._models_py3 import TargetInput
except (SyntaxError, ImportError):
    from ._models import BatchRequest  # type: ignore
    from ._models import BatchStatusDetail  # type: ignore
    from ._models import BatchStatusResponse  # type: ignore
    from ._models import BatchSubmissionRequest  # type: ignore
    from ._models import DocumentFilter  # type: ignore
    from ._models import DocumentStatusDetail  # type: ignore
    from ._models import DocumentStatusResponse  # type: ignore
    from ._models import ErrorResponseV2  # type: ignore
    from ._models import ErrorV2  # type: ignore
    from ._models import FileFormat  # type: ignore
    from ._models import FileFormatListResult  # type: ignore
    from ._models import Glossary  # type: ignore
    from ._models import InnerErrorV2  # type: ignore
    from ._models import SourceInput  # type: ignore
    from ._models import StatusSummary  # type: ignore
    from ._models import StorageSourceListResult  # type: ignore
    from ._models import TargetInput  # type: ignore

from ._batch_document_translation_client_enums import (
    ErrorCodeV2,
    Status,
    StorageInputType,
    StorageSource,
)

__all__ = [
    'BatchRequest',
    'BatchStatusDetail',
    'BatchStatusResponse',
    'BatchSubmissionRequest',
    'DocumentFilter',
    'DocumentStatusDetail',
    'DocumentStatusResponse',
    'ErrorResponseV2',
    'ErrorV2',
    'FileFormat',
    'FileFormatListResult',
    'Glossary',
    'InnerErrorV2',
    'SourceInput',
    'StatusSummary',
    'StorageSourceListResult',
    'TargetInput',
    'ErrorCodeV2',
    'Status',
    'StorageInputType',
    'StorageSource',
]
