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

try:
    from ._models_py3 import AdultInfo
    from ._models_py3 import AnalyzeResults
    from ._models_py3 import Appearance
    from ._models_py3 import AreaOfInterestResult
    from ._models_py3 import BoundingRect
    from ._models_py3 import Category
    from ._models_py3 import CategoryDetail
    from ._models_py3 import CelebritiesModel
    from ._models_py3 import ColorInfo
    from ._models_py3 import ComputerVisionError
    from ._models_py3 import ComputerVisionErrorResponse, ComputerVisionErrorResponseException
    from ._models_py3 import ComputerVisionInnerError
    from ._models_py3 import ComputerVisionOcrError, ComputerVisionOcrErrorException
    from ._models_py3 import DetectedBrand
    from ._models_py3 import DetectedObject
    from ._models_py3 import DetectResult
    from ._models_py3 import DomainModelResults
    from ._models_py3 import FaceDescription
    from ._models_py3 import FaceRectangle
    from ._models_py3 import ImageAnalysis
    from ._models_py3 import ImageCaption
    from ._models_py3 import ImageDescription
    from ._models_py3 import ImageDescriptionDetails
    from ._models_py3 import ImageMetadata
    from ._models_py3 import ImageTag
    from ._models_py3 import ImageType
    from ._models_py3 import ImageUrl
    from ._models_py3 import LandmarksModel
    from ._models_py3 import Line
    from ._models_py3 import ListModelsResult
    from ._models_py3 import ModelDescription
    from ._models_py3 import ObjectHierarchy
    from ._models_py3 import OcrLine
    from ._models_py3 import OcrRegion
    from ._models_py3 import OcrResult
    from ._models_py3 import OcrWord
    from ._models_py3 import ReadOperationResult
    from ._models_py3 import ReadResult
    from ._models_py3 import Style
    from ._models_py3 import TagResult
    from ._models_py3 import Word
except (SyntaxError, ImportError):
    from ._models import AdultInfo
    from ._models import AnalyzeResults
    from ._models import Appearance
    from ._models import AreaOfInterestResult
    from ._models import BoundingRect
    from ._models import Category
    from ._models import CategoryDetail
    from ._models import CelebritiesModel
    from ._models import ColorInfo
    from ._models import ComputerVisionError
    from ._models import ComputerVisionErrorResponse, ComputerVisionErrorResponseException
    from ._models import ComputerVisionInnerError
    from ._models import ComputerVisionOcrError, ComputerVisionOcrErrorException
    from ._models import DetectedBrand
    from ._models import DetectedObject
    from ._models import DetectResult
    from ._models import DomainModelResults
    from ._models import FaceDescription
    from ._models import FaceRectangle
    from ._models import ImageAnalysis
    from ._models import ImageCaption
    from ._models import ImageDescription
    from ._models import ImageDescriptionDetails
    from ._models import ImageMetadata
    from ._models import ImageTag
    from ._models import ImageType
    from ._models import ImageUrl
    from ._models import LandmarksModel
    from ._models import Line
    from ._models import ListModelsResult
    from ._models import ModelDescription
    from ._models import ObjectHierarchy
    from ._models import OcrLine
    from ._models import OcrRegion
    from ._models import OcrResult
    from ._models import OcrWord
    from ._models import ReadOperationResult
    from ._models import ReadResult
    from ._models import Style
    from ._models import TagResult
    from ._models import Word
from ._computer_vision_client_enums import (
    ComputerVisionErrorCodes,
    ComputerVisionInnerErrorCodeValue,
    DescriptionExclude,
    Details,
    Gender,
    OcrDetectionLanguage,
    OcrLanguages,
    OperationStatusCodes,
    TextRecognitionResultDimensionUnit,
    TextStyle,
    VisualFeatureTypes,
)

__all__ = [
    'AdultInfo',
    'AnalyzeResults',
    'Appearance',
    'AreaOfInterestResult',
    'BoundingRect',
    'Category',
    'CategoryDetail',
    'CelebritiesModel',
    'ColorInfo',
    'ComputerVisionError',
    'ComputerVisionErrorResponse', 'ComputerVisionErrorResponseException',
    'ComputerVisionInnerError',
    'ComputerVisionOcrError', 'ComputerVisionOcrErrorException',
    'DetectedBrand',
    'DetectedObject',
    'DetectResult',
    'DomainModelResults',
    'FaceDescription',
    'FaceRectangle',
    'ImageAnalysis',
    'ImageCaption',
    'ImageDescription',
    'ImageDescriptionDetails',
    'ImageMetadata',
    'ImageTag',
    'ImageType',
    'ImageUrl',
    'LandmarksModel',
    'Line',
    'ListModelsResult',
    'ModelDescription',
    'ObjectHierarchy',
    'OcrLine',
    'OcrRegion',
    'OcrResult',
    'OcrWord',
    'ReadOperationResult',
    'ReadResult',
    'Style',
    'TagResult',
    'Word',
    'Gender',
    'ComputerVisionErrorCodes',
    'ComputerVisionInnerErrorCodeValue',
    'OperationStatusCodes',
    'TextRecognitionResultDimensionUnit',
    'TextStyle',
    'DescriptionExclude',
    'OcrLanguages',
    'VisualFeatureTypes',
    'OcrDetectionLanguage',
    'Details',
]
