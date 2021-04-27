# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AlertResult
    from ._models_py3 import AlertResultList
    from ._models_py3 import AlertSnoozeCondition
    from ._models_py3 import AlertingResultQuery
    from ._models_py3 import AnomalyAlertingConfiguration
    from ._models_py3 import AnomalyAlertingConfigurationList
    from ._models_py3 import AnomalyAlertingConfigurationPatch
    from ._models_py3 import AnomalyDetectionConfiguration
    from ._models_py3 import AnomalyDetectionConfigurationList
    from ._models_py3 import AnomalyDetectionConfigurationPatch
    from ._models_py3 import AnomalyDimensionList
    from ._models_py3 import AnomalyDimensionQuery
    from ._models_py3 import AnomalyFeedback
    from ._models_py3 import AnomalyFeedbackValue
    from ._models_py3 import AnomalyProperty
    from ._models_py3 import AnomalyResult
    from ._models_py3 import AnomalyResultList
    from ._models_py3 import AzureApplicationInsightsDataFeed
    from ._models_py3 import AzureApplicationInsightsDataFeedPatch
    from ._models_py3 import AzureApplicationInsightsParameter
    from ._models_py3 import AzureBlobDataFeed
    from ._models_py3 import AzureBlobDataFeedPatch
    from ._models_py3 import AzureBlobParameter
    from ._models_py3 import AzureCosmosDBDataFeed
    from ._models_py3 import AzureCosmosDBDataFeedPatch
    from ._models_py3 import AzureCosmosDBParameter
    from ._models_py3 import AzureDataExplorerDataFeed
    from ._models_py3 import AzureDataExplorerDataFeedPatch
    from ._models_py3 import AzureDataLakeStorageGen2DataFeed
    from ._models_py3 import AzureDataLakeStorageGen2DataFeedPatch
    from ._models_py3 import AzureDataLakeStorageGen2Parameter
    from ._models_py3 import AzureEventHubsDataFeed
    from ._models_py3 import AzureEventHubsDataFeedPatch
    from ._models_py3 import AzureEventHubsParameter
    from ._models_py3 import AzureSQLConnectionStringCredential
    from ._models_py3 import AzureSQLConnectionStringCredentialPatch
    from ._models_py3 import AzureSQLConnectionStringParam
    from ._models_py3 import AzureTableDataFeed
    from ._models_py3 import AzureTableDataFeedPatch
    from ._models_py3 import AzureTableParameter
    from ._models_py3 import ChangePointFeedback
    from ._models_py3 import ChangePointFeedbackValue
    from ._models_py3 import ChangeThresholdCondition
    from ._models_py3 import CommentFeedback
    from ._models_py3 import CommentFeedbackValue
    from ._models_py3 import DataFeedDetail
    from ._models_py3 import DataFeedDetailPatch
    from ._models_py3 import DataFeedIngestionProgress
    from ._models_py3 import DataFeedList
    from ._models_py3 import DataLakeGen2SharedKeyCredential
    from ._models_py3 import DataLakeGen2SharedKeyCredentialPatch
    from ._models_py3 import DataLakeGen2SharedKeyParam
    from ._models_py3 import DataSourceCredential
    from ._models_py3 import DataSourceCredentialList
    from ._models_py3 import DataSourceCredentialPatch
    from ._models_py3 import DetectionAnomalyFilterCondition
    from ._models_py3 import DetectionAnomalyResultQuery
    from ._models_py3 import DetectionIncidentFilterCondition
    from ._models_py3 import DetectionIncidentResultQuery
    from ._models_py3 import DetectionSeriesQuery
    from ._models_py3 import Dimension
    from ._models_py3 import DimensionGroupConfiguration
    from ._models_py3 import DimensionGroupIdentity
    from ._models_py3 import ElasticsearchDataFeed
    from ._models_py3 import ElasticsearchDataFeedPatch
    from ._models_py3 import ElasticsearchParameter
    from ._models_py3 import EmailHookInfo
    from ._models_py3 import EmailHookInfoPatch
    from ._models_py3 import EmailHookParameter
    from ._models_py3 import EnrichmentStatus
    from ._models_py3 import EnrichmentStatusList
    from ._models_py3 import EnrichmentStatusQueryOption
    from ._models_py3 import ErrorCode
    from ._models_py3 import FeedbackDimensionFilter
    from ._models_py3 import HardThresholdCondition
    from ._models_py3 import HookInfo
    from ._models_py3 import HookInfoPatch
    from ._models_py3 import HookList
    from ._models_py3 import HttpRequestDataFeed
    from ._models_py3 import HttpRequestDataFeedPatch
    from ._models_py3 import HttpRequestParameter
    from ._models_py3 import IncidentProperty
    from ._models_py3 import IncidentResult
    from ._models_py3 import IncidentResultList
    from ._models_py3 import InfluxDBDataFeed
    from ._models_py3 import InfluxDBDataFeedPatch
    from ._models_py3 import InfluxDBParameter
    from ._models_py3 import IngestionProgressResetOptions
    from ._models_py3 import IngestionStatus
    from ._models_py3 import IngestionStatusList
    from ._models_py3 import IngestionStatusQueryOptions
    from ._models_py3 import Metric
    from ._models_py3 import MetricAlertingConfiguration
    from ._models_py3 import MetricDataItem
    from ._models_py3 import MetricDataList
    from ._models_py3 import MetricDataQueryOptions
    from ._models_py3 import MetricDimensionList
    from ._models_py3 import MetricDimensionQueryOptions
    from ._models_py3 import MetricFeedback
    from ._models_py3 import MetricFeedbackFilter
    from ._models_py3 import MetricFeedbackList
    from ._models_py3 import MetricSeriesItem
    from ._models_py3 import MetricSeriesList
    from ._models_py3 import MetricSeriesQueryOptions
    from ._models_py3 import MongoDBDataFeed
    from ._models_py3 import MongoDBDataFeedPatch
    from ._models_py3 import MongoDBParameter
    from ._models_py3 import MySqlDataFeed
    from ._models_py3 import MySqlDataFeedPatch
    from ._models_py3 import PeriodFeedback
    from ._models_py3 import PeriodFeedbackValue
    from ._models_py3 import PostgreSqlDataFeed
    from ._models_py3 import PostgreSqlDataFeedPatch
    from ._models_py3 import RootCause
    from ._models_py3 import RootCauseList
    from ._models_py3 import SQLServerDataFeed
    from ._models_py3 import SQLServerDataFeedPatch
    from ._models_py3 import SeriesConfiguration
    from ._models_py3 import SeriesIdentity
    from ._models_py3 import SeriesResult
    from ._models_py3 import SeriesResultList
    from ._models_py3 import ServicePrincipalCredential
    from ._models_py3 import ServicePrincipalCredentialPatch
    from ._models_py3 import ServicePrincipalInKVCredential
    from ._models_py3 import ServicePrincipalInKVCredentialPatch
    from ._models_py3 import ServicePrincipalInKVParam
    from ._models_py3 import ServicePrincipalParam
    from ._models_py3 import SeverityCondition
    from ._models_py3 import SeverityFilterCondition
    from ._models_py3 import SmartDetectionCondition
    from ._models_py3 import SqlSourceParameter
    from ._models_py3 import SuppressCondition
    from ._models_py3 import TopNGroupScope
    from ._models_py3 import UsageStats
    from ._models_py3 import ValueCondition
    from ._models_py3 import WebhookHookInfo
    from ._models_py3 import WebhookHookInfoPatch
    from ._models_py3 import WebhookHookParameter
    from ._models_py3 import WholeMetricConfiguration
except (SyntaxError, ImportError):
    from ._models import AlertResult  # type: ignore
    from ._models import AlertResultList  # type: ignore
    from ._models import AlertSnoozeCondition  # type: ignore
    from ._models import AlertingResultQuery  # type: ignore
    from ._models import AnomalyAlertingConfiguration  # type: ignore
    from ._models import AnomalyAlertingConfigurationList  # type: ignore
    from ._models import AnomalyAlertingConfigurationPatch  # type: ignore
    from ._models import AnomalyDetectionConfiguration  # type: ignore
    from ._models import AnomalyDetectionConfigurationList  # type: ignore
    from ._models import AnomalyDetectionConfigurationPatch  # type: ignore
    from ._models import AnomalyDimensionList  # type: ignore
    from ._models import AnomalyDimensionQuery  # type: ignore
    from ._models import AnomalyFeedback  # type: ignore
    from ._models import AnomalyFeedbackValue  # type: ignore
    from ._models import AnomalyProperty  # type: ignore
    from ._models import AnomalyResult  # type: ignore
    from ._models import AnomalyResultList  # type: ignore
    from ._models import AzureApplicationInsightsDataFeed  # type: ignore
    from ._models import AzureApplicationInsightsDataFeedPatch  # type: ignore
    from ._models import AzureApplicationInsightsParameter  # type: ignore
    from ._models import AzureBlobDataFeed  # type: ignore
    from ._models import AzureBlobDataFeedPatch  # type: ignore
    from ._models import AzureBlobParameter  # type: ignore
    from ._models import AzureCosmosDBDataFeed  # type: ignore
    from ._models import AzureCosmosDBDataFeedPatch  # type: ignore
    from ._models import AzureCosmosDBParameter  # type: ignore
    from ._models import AzureDataExplorerDataFeed  # type: ignore
    from ._models import AzureDataExplorerDataFeedPatch  # type: ignore
    from ._models import AzureDataLakeStorageGen2DataFeed  # type: ignore
    from ._models import AzureDataLakeStorageGen2DataFeedPatch  # type: ignore
    from ._models import AzureDataLakeStorageGen2Parameter  # type: ignore
    from ._models import AzureEventHubsDataFeed  # type: ignore
    from ._models import AzureEventHubsDataFeedPatch  # type: ignore
    from ._models import AzureEventHubsParameter  # type: ignore
    from ._models import AzureSQLConnectionStringCredential  # type: ignore
    from ._models import AzureSQLConnectionStringCredentialPatch  # type: ignore
    from ._models import AzureSQLConnectionStringParam  # type: ignore
    from ._models import AzureTableDataFeed  # type: ignore
    from ._models import AzureTableDataFeedPatch  # type: ignore
    from ._models import AzureTableParameter  # type: ignore
    from ._models import ChangePointFeedback  # type: ignore
    from ._models import ChangePointFeedbackValue  # type: ignore
    from ._models import ChangeThresholdCondition  # type: ignore
    from ._models import CommentFeedback  # type: ignore
    from ._models import CommentFeedbackValue  # type: ignore
    from ._models import DataFeedDetail  # type: ignore
    from ._models import DataFeedDetailPatch  # type: ignore
    from ._models import DataFeedIngestionProgress  # type: ignore
    from ._models import DataFeedList  # type: ignore
    from ._models import DataLakeGen2SharedKeyCredential  # type: ignore
    from ._models import DataLakeGen2SharedKeyCredentialPatch  # type: ignore
    from ._models import DataLakeGen2SharedKeyParam  # type: ignore
    from ._models import DataSourceCredential  # type: ignore
    from ._models import DataSourceCredentialList  # type: ignore
    from ._models import DataSourceCredentialPatch  # type: ignore
    from ._models import DetectionAnomalyFilterCondition  # type: ignore
    from ._models import DetectionAnomalyResultQuery  # type: ignore
    from ._models import DetectionIncidentFilterCondition  # type: ignore
    from ._models import DetectionIncidentResultQuery  # type: ignore
    from ._models import DetectionSeriesQuery  # type: ignore
    from ._models import Dimension  # type: ignore
    from ._models import DimensionGroupConfiguration  # type: ignore
    from ._models import DimensionGroupIdentity  # type: ignore
    from ._models import ElasticsearchDataFeed  # type: ignore
    from ._models import ElasticsearchDataFeedPatch  # type: ignore
    from ._models import ElasticsearchParameter  # type: ignore
    from ._models import EmailHookInfo  # type: ignore
    from ._models import EmailHookInfoPatch  # type: ignore
    from ._models import EmailHookParameter  # type: ignore
    from ._models import EnrichmentStatus  # type: ignore
    from ._models import EnrichmentStatusList  # type: ignore
    from ._models import EnrichmentStatusQueryOption  # type: ignore
    from ._models import ErrorCode  # type: ignore
    from ._models import FeedbackDimensionFilter  # type: ignore
    from ._models import HardThresholdCondition  # type: ignore
    from ._models import HookInfo  # type: ignore
    from ._models import HookInfoPatch  # type: ignore
    from ._models import HookList  # type: ignore
    from ._models import HttpRequestDataFeed  # type: ignore
    from ._models import HttpRequestDataFeedPatch  # type: ignore
    from ._models import HttpRequestParameter  # type: ignore
    from ._models import IncidentProperty  # type: ignore
    from ._models import IncidentResult  # type: ignore
    from ._models import IncidentResultList  # type: ignore
    from ._models import InfluxDBDataFeed  # type: ignore
    from ._models import InfluxDBDataFeedPatch  # type: ignore
    from ._models import InfluxDBParameter  # type: ignore
    from ._models import IngestionProgressResetOptions  # type: ignore
    from ._models import IngestionStatus  # type: ignore
    from ._models import IngestionStatusList  # type: ignore
    from ._models import IngestionStatusQueryOptions  # type: ignore
    from ._models import Metric  # type: ignore
    from ._models import MetricAlertingConfiguration  # type: ignore
    from ._models import MetricDataItem  # type: ignore
    from ._models import MetricDataList  # type: ignore
    from ._models import MetricDataQueryOptions  # type: ignore
    from ._models import MetricDimensionList  # type: ignore
    from ._models import MetricDimensionQueryOptions  # type: ignore
    from ._models import MetricFeedback  # type: ignore
    from ._models import MetricFeedbackFilter  # type: ignore
    from ._models import MetricFeedbackList  # type: ignore
    from ._models import MetricSeriesItem  # type: ignore
    from ._models import MetricSeriesList  # type: ignore
    from ._models import MetricSeriesQueryOptions  # type: ignore
    from ._models import MongoDBDataFeed  # type: ignore
    from ._models import MongoDBDataFeedPatch  # type: ignore
    from ._models import MongoDBParameter  # type: ignore
    from ._models import MySqlDataFeed  # type: ignore
    from ._models import MySqlDataFeedPatch  # type: ignore
    from ._models import PeriodFeedback  # type: ignore
    from ._models import PeriodFeedbackValue  # type: ignore
    from ._models import PostgreSqlDataFeed  # type: ignore
    from ._models import PostgreSqlDataFeedPatch  # type: ignore
    from ._models import RootCause  # type: ignore
    from ._models import RootCauseList  # type: ignore
    from ._models import SQLServerDataFeed  # type: ignore
    from ._models import SQLServerDataFeedPatch  # type: ignore
    from ._models import SeriesConfiguration  # type: ignore
    from ._models import SeriesIdentity  # type: ignore
    from ._models import SeriesResult  # type: ignore
    from ._models import SeriesResultList  # type: ignore
    from ._models import ServicePrincipalCredential  # type: ignore
    from ._models import ServicePrincipalCredentialPatch  # type: ignore
    from ._models import ServicePrincipalInKVCredential  # type: ignore
    from ._models import ServicePrincipalInKVCredentialPatch  # type: ignore
    from ._models import ServicePrincipalInKVParam  # type: ignore
    from ._models import ServicePrincipalParam  # type: ignore
    from ._models import SeverityCondition  # type: ignore
    from ._models import SeverityFilterCondition  # type: ignore
    from ._models import SmartDetectionCondition  # type: ignore
    from ._models import SqlSourceParameter  # type: ignore
    from ._models import SuppressCondition  # type: ignore
    from ._models import TopNGroupScope  # type: ignore
    from ._models import UsageStats  # type: ignore
    from ._models import ValueCondition  # type: ignore
    from ._models import WebhookHookInfo  # type: ignore
    from ._models import WebhookHookInfoPatch  # type: ignore
    from ._models import WebhookHookParameter  # type: ignore
    from ._models import WholeMetricConfiguration  # type: ignore

from ._azure_cognitive_service_metrics_advisor_restapi_open_ap_iv2_enums import (
    AnomalyAlertingConfigurationLogicType,
    AnomalyDetectionConfigurationLogicType,
    AnomalyDetectorDirection,
    AnomalyScope,
    AnomalyStatus,
    AnomalyValue,
    AuthenticationTypeEnum,
    ChangePointValue,
    DataSourceCredentialType,
    DataSourceType,
    Direction,
    EntityStatus,
    FeedbackQueryTimeMode,
    FeedbackType,
    FillMissingPointType,
    Granularity,
    HookType,
    IncidentStatus,
    IngestionStatusType,
    NeedRollupEnum,
    PeriodType,
    RollUpMethod,
    Severity,
    SnoozeScope,
    TimeMode,
    ValueType,
    ViewMode,
)

__all__ = [
    'AlertResult',
    'AlertResultList',
    'AlertSnoozeCondition',
    'AlertingResultQuery',
    'AnomalyAlertingConfiguration',
    'AnomalyAlertingConfigurationList',
    'AnomalyAlertingConfigurationPatch',
    'AnomalyDetectionConfiguration',
    'AnomalyDetectionConfigurationList',
    'AnomalyDetectionConfigurationPatch',
    'AnomalyDimensionList',
    'AnomalyDimensionQuery',
    'AnomalyFeedback',
    'AnomalyFeedbackValue',
    'AnomalyProperty',
    'AnomalyResult',
    'AnomalyResultList',
    'AzureApplicationInsightsDataFeed',
    'AzureApplicationInsightsDataFeedPatch',
    'AzureApplicationInsightsParameter',
    'AzureBlobDataFeed',
    'AzureBlobDataFeedPatch',
    'AzureBlobParameter',
    'AzureCosmosDBDataFeed',
    'AzureCosmosDBDataFeedPatch',
    'AzureCosmosDBParameter',
    'AzureDataExplorerDataFeed',
    'AzureDataExplorerDataFeedPatch',
    'AzureDataLakeStorageGen2DataFeed',
    'AzureDataLakeStorageGen2DataFeedPatch',
    'AzureDataLakeStorageGen2Parameter',
    'AzureEventHubsDataFeed',
    'AzureEventHubsDataFeedPatch',
    'AzureEventHubsParameter',
    'AzureSQLConnectionStringCredential',
    'AzureSQLConnectionStringCredentialPatch',
    'AzureSQLConnectionStringParam',
    'AzureTableDataFeed',
    'AzureTableDataFeedPatch',
    'AzureTableParameter',
    'ChangePointFeedback',
    'ChangePointFeedbackValue',
    'ChangeThresholdCondition',
    'CommentFeedback',
    'CommentFeedbackValue',
    'DataFeedDetail',
    'DataFeedDetailPatch',
    'DataFeedIngestionProgress',
    'DataFeedList',
    'DataLakeGen2SharedKeyCredential',
    'DataLakeGen2SharedKeyCredentialPatch',
    'DataLakeGen2SharedKeyParam',
    'DataSourceCredential',
    'DataSourceCredentialList',
    'DataSourceCredentialPatch',
    'DetectionAnomalyFilterCondition',
    'DetectionAnomalyResultQuery',
    'DetectionIncidentFilterCondition',
    'DetectionIncidentResultQuery',
    'DetectionSeriesQuery',
    'Dimension',
    'DimensionGroupConfiguration',
    'DimensionGroupIdentity',
    'ElasticsearchDataFeed',
    'ElasticsearchDataFeedPatch',
    'ElasticsearchParameter',
    'EmailHookInfo',
    'EmailHookInfoPatch',
    'EmailHookParameter',
    'EnrichmentStatus',
    'EnrichmentStatusList',
    'EnrichmentStatusQueryOption',
    'ErrorCode',
    'FeedbackDimensionFilter',
    'HardThresholdCondition',
    'HookInfo',
    'HookInfoPatch',
    'HookList',
    'HttpRequestDataFeed',
    'HttpRequestDataFeedPatch',
    'HttpRequestParameter',
    'IncidentProperty',
    'IncidentResult',
    'IncidentResultList',
    'InfluxDBDataFeed',
    'InfluxDBDataFeedPatch',
    'InfluxDBParameter',
    'IngestionProgressResetOptions',
    'IngestionStatus',
    'IngestionStatusList',
    'IngestionStatusQueryOptions',
    'Metric',
    'MetricAlertingConfiguration',
    'MetricDataItem',
    'MetricDataList',
    'MetricDataQueryOptions',
    'MetricDimensionList',
    'MetricDimensionQueryOptions',
    'MetricFeedback',
    'MetricFeedbackFilter',
    'MetricFeedbackList',
    'MetricSeriesItem',
    'MetricSeriesList',
    'MetricSeriesQueryOptions',
    'MongoDBDataFeed',
    'MongoDBDataFeedPatch',
    'MongoDBParameter',
    'MySqlDataFeed',
    'MySqlDataFeedPatch',
    'PeriodFeedback',
    'PeriodFeedbackValue',
    'PostgreSqlDataFeed',
    'PostgreSqlDataFeedPatch',
    'RootCause',
    'RootCauseList',
    'SQLServerDataFeed',
    'SQLServerDataFeedPatch',
    'SeriesConfiguration',
    'SeriesIdentity',
    'SeriesResult',
    'SeriesResultList',
    'ServicePrincipalCredential',
    'ServicePrincipalCredentialPatch',
    'ServicePrincipalInKVCredential',
    'ServicePrincipalInKVCredentialPatch',
    'ServicePrincipalInKVParam',
    'ServicePrincipalParam',
    'SeverityCondition',
    'SeverityFilterCondition',
    'SmartDetectionCondition',
    'SqlSourceParameter',
    'SuppressCondition',
    'TopNGroupScope',
    'UsageStats',
    'ValueCondition',
    'WebhookHookInfo',
    'WebhookHookInfoPatch',
    'WebhookHookParameter',
    'WholeMetricConfiguration',
    'AnomalyAlertingConfigurationLogicType',
    'AnomalyDetectionConfigurationLogicType',
    'AnomalyDetectorDirection',
    'AnomalyScope',
    'AnomalyStatus',
    'AnomalyValue',
    'AuthenticationTypeEnum',
    'ChangePointValue',
    'DataSourceCredentialType',
    'DataSourceType',
    'Direction',
    'EntityStatus',
    'FeedbackQueryTimeMode',
    'FeedbackType',
    'FillMissingPointType',
    'Granularity',
    'HookType',
    'IncidentStatus',
    'IngestionStatusType',
    'NeedRollupEnum',
    'PeriodType',
    'RollUpMethod',
    'Severity',
    'SnoozeScope',
    'TimeMode',
    'ValueType',
    'ViewMode',
]
