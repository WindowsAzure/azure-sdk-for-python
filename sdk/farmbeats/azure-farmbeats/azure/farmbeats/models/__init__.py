# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.1.3, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import ApplicationData
    from ._models_py3 import ApplicationDataListResponse
    from ._models_py3 import ApplicationProductDetail
    from ._models_py3 import Attachment
    from ._models_py3 import AttachmentListResponse
    from ._models_py3 import Boundary
    from ._models_py3 import BoundaryListResponse
    from ._models_py3 import BoundaryOverlapResponse
    from ._models_py3 import CascadeDeleteJobRequest
    from ._models_py3 import CascadeDeleteJobResponse
    from ._models_py3 import CascadeStatusUpdateJobRequest
    from ._models_py3 import CascadeStatusUpdateJobResponse
    from ._models_py3 import Crop
    from ._models_py3 import CropListResponse
    from ._models_py3 import CropVariety
    from ._models_py3 import CropVarietyListResponse
    from ._models_py3 import Error
    from ._models_py3 import ErrorResponse
    from ._models_py3 import Farm
    from ._models_py3 import FarmListResponse
    from ._models_py3 import FarmOperationDataIngestionJobRequest
    from ._models_py3 import FarmOperationDataIngestionJobResponse
    from ._models_py3 import Farmer
    from ._models_py3 import FarmerListResponse
    from ._models_py3 import Field
    from ._models_py3 import FieldListResponse
    from ._models_py3 import GeoJsonObject
    from ._models_py3 import HarvestData
    from ._models_py3 import HarvestDataListResponse
    from ._models_py3 import HarvestProductDetail
    from ._models_py3 import ImageFileResponse
    from ._models_py3 import InnerError
    from ._models_py3 import JobResponse
    from ._models_py3 import Location
    from ._models_py3 import Measure
    from ._models_py3 import MultiPolygon
    from ._models_py3 import OAuthConfig
    from ._models_py3 import OAuthConfigQuery
    from ._models_py3 import OAuthProvider
    from ._models_py3 import OAuthProviderListResponse
    from ._models_py3 import OAuthTokenInfo
    from ._models_py3 import OAuthTokenInfoListResponse
    from ._models_py3 import Paths104Hgf2FarmersFarmeridAttachmentsAttachmentidPutRequestbodyContentMultipartFormDataSchema
    from ._models_py3 import Paths1LxjoxzFarmersFarmeridAttachmentsAttachmentidPatchRequestbodyContentMultipartFormDataSchema
    from ._models_py3 import PlantingData
    from ._models_py3 import PlantingDataListResponse
    from ._models_py3 import Point
    from ._models_py3 import Polygon
    from ._models_py3 import SatelliteData
    from ._models_py3 import SatelliteIngestionJobRequest
    from ._models_py3 import SatelliteIngestionJobResponse
    from ._models_py3 import SceneEntityResponse
    from ._models_py3 import SceneEntityResponseListResponse
    from ._models_py3 import SearchBoundaryQuery
    from ._models_py3 import Season
    from ._models_py3 import SeasonListResponse
    from ._models_py3 import SeasonalField
    from ._models_py3 import SeasonalFieldListResponse
    from ._models_py3 import SeedingProductDetail
    from ._models_py3 import TillageData
    from ._models_py3 import TillageDataListResponse
    from ._models_py3 import WeatherData
    from ._models_py3 import WeatherDataDeleteJobRequest
    from ._models_py3 import WeatherDataDeleteJobResponse
    from ._models_py3 import WeatherDataListResponse
    from ._models_py3 import WeatherIngestionJobRequest
    from ._models_py3 import WeatherIngestionJobResponse
    from ._models_py3 import WeatherMeasure
except (SyntaxError, ImportError):
    from ._models import ApplicationData  # type: ignore
    from ._models import ApplicationDataListResponse  # type: ignore
    from ._models import ApplicationProductDetail  # type: ignore
    from ._models import Attachment  # type: ignore
    from ._models import AttachmentListResponse  # type: ignore
    from ._models import Boundary  # type: ignore
    from ._models import BoundaryListResponse  # type: ignore
    from ._models import BoundaryOverlapResponse  # type: ignore
    from ._models import CascadeDeleteJobRequest  # type: ignore
    from ._models import CascadeDeleteJobResponse  # type: ignore
    from ._models import CascadeStatusUpdateJobRequest  # type: ignore
    from ._models import CascadeStatusUpdateJobResponse  # type: ignore
    from ._models import Crop  # type: ignore
    from ._models import CropListResponse  # type: ignore
    from ._models import CropVariety  # type: ignore
    from ._models import CropVarietyListResponse  # type: ignore
    from ._models import Error  # type: ignore
    from ._models import ErrorResponse  # type: ignore
    from ._models import Farm  # type: ignore
    from ._models import FarmListResponse  # type: ignore
    from ._models import FarmOperationDataIngestionJobRequest  # type: ignore
    from ._models import FarmOperationDataIngestionJobResponse  # type: ignore
    from ._models import Farmer  # type: ignore
    from ._models import FarmerListResponse  # type: ignore
    from ._models import Field  # type: ignore
    from ._models import FieldListResponse  # type: ignore
    from ._models import GeoJsonObject  # type: ignore
    from ._models import HarvestData  # type: ignore
    from ._models import HarvestDataListResponse  # type: ignore
    from ._models import HarvestProductDetail  # type: ignore
    from ._models import ImageFileResponse  # type: ignore
    from ._models import InnerError  # type: ignore
    from ._models import JobResponse  # type: ignore
    from ._models import Location  # type: ignore
    from ._models import Measure  # type: ignore
    from ._models import MultiPolygon  # type: ignore
    from ._models import OAuthConfig  # type: ignore
    from ._models import OAuthConfigQuery  # type: ignore
    from ._models import OAuthProvider  # type: ignore
    from ._models import OAuthProviderListResponse  # type: ignore
    from ._models import OAuthTokenInfo  # type: ignore
    from ._models import OAuthTokenInfoListResponse  # type: ignore
    from ._models import Paths104Hgf2FarmersFarmeridAttachmentsAttachmentidPutRequestbodyContentMultipartFormDataSchema  # type: ignore
    from ._models import Paths1LxjoxzFarmersFarmeridAttachmentsAttachmentidPatchRequestbodyContentMultipartFormDataSchema  # type: ignore
    from ._models import PlantingData  # type: ignore
    from ._models import PlantingDataListResponse  # type: ignore
    from ._models import Point  # type: ignore
    from ._models import Polygon  # type: ignore
    from ._models import SatelliteData  # type: ignore
    from ._models import SatelliteIngestionJobRequest  # type: ignore
    from ._models import SatelliteIngestionJobResponse  # type: ignore
    from ._models import SceneEntityResponse  # type: ignore
    from ._models import SceneEntityResponseListResponse  # type: ignore
    from ._models import SearchBoundaryQuery  # type: ignore
    from ._models import Season  # type: ignore
    from ._models import SeasonListResponse  # type: ignore
    from ._models import SeasonalField  # type: ignore
    from ._models import SeasonalFieldListResponse  # type: ignore
    from ._models import SeedingProductDetail  # type: ignore
    from ._models import TillageData  # type: ignore
    from ._models import TillageDataListResponse  # type: ignore
    from ._models import WeatherData  # type: ignore
    from ._models import WeatherDataDeleteJobRequest  # type: ignore
    from ._models import WeatherDataDeleteJobResponse  # type: ignore
    from ._models import WeatherDataListResponse  # type: ignore
    from ._models import WeatherIngestionJobRequest  # type: ignore
    from ._models import WeatherIngestionJobResponse  # type: ignore
    from ._models import WeatherMeasure  # type: ignore

from ._farm_beats_client_enums import (
    DataProvider,
    FieldOperationType,
    GeoJsonObjectType,
    ImageFormat,
    ImageName,
    ImageResolution,
    JobStatus,
    Source,
)

__all__ = [
    'ApplicationData',
    'ApplicationDataListResponse',
    'ApplicationProductDetail',
    'Attachment',
    'AttachmentListResponse',
    'Boundary',
    'BoundaryListResponse',
    'BoundaryOverlapResponse',
    'CascadeDeleteJobRequest',
    'CascadeDeleteJobResponse',
    'CascadeStatusUpdateJobRequest',
    'CascadeStatusUpdateJobResponse',
    'Crop',
    'CropListResponse',
    'CropVariety',
    'CropVarietyListResponse',
    'Error',
    'ErrorResponse',
    'Farm',
    'FarmListResponse',
    'FarmOperationDataIngestionJobRequest',
    'FarmOperationDataIngestionJobResponse',
    'Farmer',
    'FarmerListResponse',
    'Field',
    'FieldListResponse',
    'GeoJsonObject',
    'HarvestData',
    'HarvestDataListResponse',
    'HarvestProductDetail',
    'ImageFileResponse',
    'InnerError',
    'JobResponse',
    'Location',
    'Measure',
    'MultiPolygon',
    'OAuthConfig',
    'OAuthConfigQuery',
    'OAuthProvider',
    'OAuthProviderListResponse',
    'OAuthTokenInfo',
    'OAuthTokenInfoListResponse',
    'Paths104Hgf2FarmersFarmeridAttachmentsAttachmentidPutRequestbodyContentMultipartFormDataSchema',
    'Paths1LxjoxzFarmersFarmeridAttachmentsAttachmentidPatchRequestbodyContentMultipartFormDataSchema',
    'PlantingData',
    'PlantingDataListResponse',
    'Point',
    'Polygon',
    'SatelliteData',
    'SatelliteIngestionJobRequest',
    'SatelliteIngestionJobResponse',
    'SceneEntityResponse',
    'SceneEntityResponseListResponse',
    'SearchBoundaryQuery',
    'Season',
    'SeasonListResponse',
    'SeasonalField',
    'SeasonalFieldListResponse',
    'SeedingProductDetail',
    'TillageData',
    'TillageDataListResponse',
    'WeatherData',
    'WeatherDataDeleteJobRequest',
    'WeatherDataDeleteJobResponse',
    'WeatherDataListResponse',
    'WeatherIngestionJobRequest',
    'WeatherIngestionJobResponse',
    'WeatherMeasure',
    'DataProvider',
    'FieldOperationType',
    'GeoJsonObjectType',
    'ImageFormat',
    'ImageName',
    'ImageResolution',
    'JobStatus',
    'Source',
]
